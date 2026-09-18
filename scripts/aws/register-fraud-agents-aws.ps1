#Requires -Version 5.1
<#
.SYNOPSIS
    Unpacks the 4 fraud-agent TAR packages (built by Agent-mongo-fraud-agents/scripts/
    Build-AgentPackages.ps1), pushes the shared image to ECR once, and registers all 4 agents
    with the AWS-deployed Mesh instance via ContainerInstance deployment.

.DESCRIPTION
    There is no working Mesh-side "upload this tar to ECR" API for AWS: the per-agent upload
    endpoint (POST .../agents/{agentId}/image) is hard-disabled whenever UseLocalDocker=false
    (this deployment), and Web's own blob-upload flow is Azure-Blob-specific with no S3
    equivalent anywhere in that repo. So this script does the unpack-and-push itself, directly —
    functionally the same one-command experience, just a plain `docker push` under the hood
    rather than a Mesh API call.

    All 4 packages share the SAME underlying image (Build-AgentPackages.ps1 builds it once) — the
    per-agent difference is only which runtime-config.json (a single {"AGENT_NAME": "..."} entry
    today, but read verbatim rather than assumed, so future keys Build-AgentPackages.ps1 might add
    survive here unchanged) gets attached at registration. So the image is loaded/tagged/pushed to
    ECR from the FIRST package only; the remaining 3 just contribute their runtime-config.json.

    ContainerImageReference is a plain string field on Mesh's registration request — nothing
    validates it came from Mesh's own upload endpoint, so a self-pushed ECR URI works identically
    (confirmed from AdminController.cs / ContainerDeploymentService.cs). Configuration (a plain
    dict on the same request) maps straight through to the container's environment variables with
    top priority — this is how one shared image becomes 4 distinct agents.

    Requires a real Mesh admin bearer token — this AWS Mesh deployment runs in Production mode
    (/local/token is disabled there), so there is no way for this script to mint one itself.

.PARAMETER MeshBaseUrl
    REQUIRED. Base URL of the AWS-deployed Mesh instance.

.PARAMETER MeshAdminToken
    REQUIRED. A real admin-role Mesh bearer token (IAM Identity Center SAML login via the
    mesh-runtime-admins Cognito pool, granting the "mesh-admins" group — same path Mesh's own
    admin operations use). No default, never logged.

.PARAMETER AgentPackagesDir
    REQUIRED. Directory containing the 4 TAR packages, named exactly
    alert_validation.tar / data_collection.tar / llm_agent.tar / report_generation.tar — matches
    Build-AgentPackages.ps1's own -OutputDir output (default ./dist/agent-packages).

.PARAMETER AgentEcrRepoName
    ECR repository to push the shared image to. Default: agents/fraud-agent (matches
    ContainerRegistry__Aws__RepositoryPrefix="agents" on the live Mesh deployment's own
    convention, though this script pushes independently of that setting since it never goes
    through Mesh's own registry-push code path).

.PARAMETER ImageTag
    Tag to push under. Default: latest.

.PARAMETER AgentClientIdPrefix
    Default: fraud-detection-agent. Each agent's ClientId becomes "<prefix>-<agentId>".

.PARAMETER AgentKeyVaultSigningKeyUri
    REQUIRED. The signing-key reference (despite the Azure-sounding name, CloudAssertionVerifierResolver
    is provider-aware — this is an AWS KMS key ARN here) used to verify each agent's client
    assertions. Shared across all 4 agents, matching how Mesh signs for itself with one key.

.PARAMETER AssertionAlgorithm
    Default: RS256.

.EXAMPLE
    ./register-fraud-agents-aws.ps1 -MeshBaseUrl "https://mesh.example.com" `
        -MeshAdminToken $env:MESH_ADMIN_TOKEN `
        -AgentPackagesDir "../Agent-mongo-fraud-agents/dist/agent-packages" `
        -AgentKeyVaultSigningKeyUri "arn:aws:kms:us-east-2:297784246949:key/..."
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "REQUIRED. Base URL of the AWS-deployed Mesh instance.")]
    [string]$MeshBaseUrl,

    [Parameter(Mandatory = $true, HelpMessage = "REQUIRED. A real admin-role Mesh bearer token. No default — never logged.")]
    [string]$MeshAdminToken,

    [Parameter(Mandatory = $true, HelpMessage = "REQUIRED. Directory containing the 4 agent TAR packages.")]
    [string]$AgentPackagesDir,

    [string]$AgentEcrRepoName = "agents/fraud-agent",
    [string]$ImageTag = "latest",
    [string]$AgentClientIdPrefix = "fraud-detection-agent",

    [Parameter(Mandatory = $true, HelpMessage = "REQUIRED. AWS KMS key ARN (or equivalent) used to verify agent assertions.")]
    [string]$AgentKeyVaultSigningKeyUri,

    [string]$AssertionAlgorithm = "RS256"
)

$ErrorActionPreference = "Stop"

$Agents = @(
    @{ Id = "alert_validation";  Name = "Alert Validation Agent";  Description = "Fraud investigation: validates and extracts context from an incoming alert"; Tag = "fraud:alert-validation" }
    @{ Id = "data_collection";   Name = "Data Collection Agent";   Description = "Fraud investigation: gathers evidence from Mongo for the alert";              Tag = "fraud:data-collection" }
    @{ Id = "llm_agent";         Name = "LLM Investigation Agent"; Description = "Fraud investigation: AI-driven analysis of gathered evidence";                Tag = "fraud:llm-investigation" }
    @{ Id = "report_generation"; Name = "Report Generation Agent"; Description = "Fraud investigation: generates the final markdown report";                   Tag = "fraud:report-generation" }
)

foreach ($agent in $Agents) {
    $tarPath = Join-Path $AgentPackagesDir "$($agent.Id).tar"
    if (-not (Test-Path $tarPath)) { throw "Package not found: $tarPath — run Build-AgentPackages.ps1 first." }
}

Write-Host "=== Verifying AWS login ===" -ForegroundColor Cyan
$callerIdentity = aws sts get-caller-identity 2>$null | ConvertFrom-Json
if (-not $callerIdentity) { throw "Not logged into AWS. Run 'aws login' (or your account's SSO equivalent) first." }
$AccountId = $callerIdentity.Account
$Region = (aws configure get region 2>$null)
if (-not $Region) { $Region = "us-east-2" }
Write-Host "Account: $AccountId, region: $Region" -ForegroundColor Green

$WorkDir = Join-Path ([System.IO.Path]::GetTempPath()) "fraud-agent-register-$(Get-Random)"
New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null

try {
    Write-Host "`n=== Ensuring ECR repository '$AgentEcrRepoName' ===" -ForegroundColor Cyan
    aws ecr describe-repositories --region $Region --repository-names $AgentEcrRepoName 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) {
        aws ecr create-repository --region $Region --repository-name $AgentEcrRepoName | Out-Null
        Write-Host "Created repository '$AgentEcrRepoName'." -ForegroundColor Gray
    }
    $ecrLoginServer = "$AccountId.dkr.ecr.$Region.amazonaws.com"
    $ecrImageUri = "${ecrLoginServer}/${AgentEcrRepoName}:${ImageTag}"

    # All 4 packages share the same underlying image — unpack/load/push from the first one only.
    Write-Host "`n=== Unpacking and pushing the shared agent image (from '$($Agents[0].Id).tar') ===" -ForegroundColor Cyan
    $firstBundleDir = Join-Path $WorkDir $Agents[0].Id
    New-Item -ItemType Directory -Path $firstBundleDir -Force | Out-Null
    tar -xf (Join-Path $AgentPackagesDir "$($Agents[0].Id).tar") -C $firstBundleDir
    if ($LASTEXITCODE -ne 0) { throw "Failed to unpack $($Agents[0].Id).tar" }

    $loadOutput = docker load -i (Join-Path $firstBundleDir "image.tar") 2>&1
    if ($LASTEXITCODE -ne 0) { throw "docker load failed: $loadOutput" }
    $loadedMatch = ($loadOutput | Select-String -Pattern "Loaded image: (.+)$")
    if (-not $loadedMatch) { throw "Could not parse loaded image reference from docker load output: $loadOutput" }
    $loadedImageRef = $loadedMatch.Matches[0].Groups[1].Value.Trim()
    Write-Host "Loaded image: $loadedImageRef" -ForegroundColor Gray

    docker tag $loadedImageRef $ecrImageUri
    if ($LASTEXITCODE -ne 0) { throw "docker tag failed" }

    aws ecr get-login-password --region $Region | docker login --username AWS --password-stdin $ecrLoginServer
    if ($LASTEXITCODE -ne 0) { throw "docker login to ECR failed" }

    docker push $ecrImageUri
    if ($LASTEXITCODE -ne 0) { throw "docker push failed" }
    Write-Host "Pushed $ecrImageUri" -ForegroundColor Green

    Write-Host "`n=== Registering agents ===" -ForegroundColor Cyan
    $headers = @{ Authorization = "Bearer $MeshAdminToken"; "Content-Type" = "application/json" }

    foreach ($agent in $Agents) {
        Write-Host "`n--- '$($agent.Id)' ---" -ForegroundColor Cyan

        # Read this agent's own runtime-config.json verbatim rather than assuming its shape —
        # Build-AgentPackages.ps1 owns what goes in it; this script shouldn't hardcode a copy
        # that could drift from it.
        $bundleDir = Join-Path $WorkDir $agent.Id
        if (-not (Test-Path $bundleDir)) {
            New-Item -ItemType Directory -Path $bundleDir -Force | Out-Null
            tar -xf (Join-Path $AgentPackagesDir "$($agent.Id).tar") -C $bundleDir "runtime-config.json"
            if ($LASTEXITCODE -ne 0) { throw "Failed to extract runtime-config.json from $($agent.Id).tar" }
        }
        $runtimeConfig = Get-Content (Join-Path $bundleDir "runtime-config.json") -Raw | ConvertFrom-Json

        $body = @{
            Id = $agent.Id
            Name = $agent.Name
            Description = $agent.Description
            AgentType = "ExecutionAgent"
            DeploymentMode = "ContainerInstance"
            IsEnabled = $true
            ContainerImageReference = $ecrImageUri
            Configuration = $runtimeConfig
            ClientId = "${AgentClientIdPrefix}-$($agent.Id)"
            KeyVaultSigningKeyUri = $AgentKeyVaultSigningKeyUri
            AssertionAlgorithm = $AssertionAlgorithm
            Tags = @($agent.Tag)
            Capabilities = @($agent.Tag)
        } | ConvertTo-Json -Depth 10

        try {
            Invoke-RestMethod -Uri "$MeshBaseUrl/api/v1/admin/agents" -Method Post -Headers $headers -Body $body | Out-Null
        } catch {
            $responseBody = $null
            if ($_.ErrorDetails) { $responseBody = $_.ErrorDetails.Message }
            throw "Failed to register '$($agent.Id)': $($_.Exception.Message)$(if ($responseBody) { " — $responseBody" })"
        }
        Write-Host "Registration submitted — deployment queued asynchronously." -ForegroundColor Green
    }
} finally {
    Remove-Item -Path $WorkDir -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "`n=== Waiting for all 4 agents to reach Ready ===" -ForegroundColor Cyan
$headers = @{ Authorization = "Bearer $MeshAdminToken" }
$maxAttempts = 30
foreach ($agent in $Agents) {
    $ready = $false
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        $status = Invoke-RestMethod -Uri "$MeshBaseUrl/api/v1/admin/agents/$($agent.Id)" -Method Get -Headers $headers
        if ($status.deploymentStatus -eq "Ready") { $ready = $true; break }
        if ($status.deploymentStatus -eq "Failed") { throw "Agent '$($agent.Id)' deployment failed — check Mesh logs." }
        Write-Host "  '$($agent.Id)': $($status.deploymentStatus) (attempt $attempt/$maxAttempts)..." -ForegroundColor Gray
        Start-Sleep -Seconds 10
    }
    if (-not $ready) { throw "Agent '$($agent.Id)' did not reach Ready within $($maxAttempts * 10)s." }
    Write-Host "'$($agent.Id)' is Ready." -ForegroundColor Green
}

Write-Host "`n✅ All 4 fraud-detection agents unpacked, pushed, and registered." -ForegroundColor Green
