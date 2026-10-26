#Requires -Version 5.1
<#
.SYNOPSIS
    Uploads the 4 fraud-agent TAR packages (built by the Agent repo's
    scripts/Build-AgentPackages.ps1) to the AWS-deployed Mesh instance and registers all 4
    agents for ContainerInstance deployment.

.DESCRIPTION
    Each package is streamed to Mesh's direct-upload endpoint
    (POST /api/v1/admin/agents/{agentId}/image), which pushes the image into Mesh's own per-agent
    ECR repository (agents/<agentId>) and returns a digest-pinned imageReference plus the
    package's runtime-config.json. Registration must carry exactly that reference as
    registryAgentImageReference — Mesh rejects a self-pushed image, another repository, or a bare
    tag. All 4 packages share the same underlying image; the per-agent difference is the
    runtime-config.json each carries, merged with this script's own settings into the
    registration's Configuration (passed through to the container's environment).

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

.PARAMETER ImageVersion
    Version tag Mesh pushes each uploaded image under (digest-pinned in the returned reference).
    Default: latest.

.PARAMETER AgentKeyVaultSigningKeyUri
    REQUIRED. The signing-key reference (despite the Azure-sounding name, CloudAssertionVerifierResolver
    is provider-aware — this is an AWS KMS key ARN here) used to verify each agent's client
    assertions. Shared across all 4 agents, matching how Mesh signs for itself with one key.

.PARAMETER AssertionAlgorithm
    Default: RS256.

.PARAMETER MongoDatabaseName
    Default: fraud_detection_demo. MUST match deploy-fraud-detection-to-aws.ps1's
    -MongoDatabaseName exactly — agents and backend share one Mongo server but pick their
    database by this name, not by the connection string's path segment.

.PARAMETER LlmProvider
    Default: gemini (matches Agent-mongo-fraud-agents/docker-compose.split.yml's local E2E setup).
    llm_agent.py / report_generation.py default to "ollama" when LLM_PROVIDER is unset, which has
    no reachable daemon inside an ECS task — set to "ollama" only if a reachable Ollama endpoint
    is configured separately.

.PARAMETER GeminiApiKey
    Required when -LlmProvider is "gemini". Defaults to $env:GEMINI_API_KEY — never hardcode this,
    never pass it where it would be logged.

.PARAMETER GeminiModel
    Default: gemini-3.5-flash-lite (matches the model actually configured on the running local
    agent container — docker-compose.split.yml's own fallback value, gemini-2.0-flash, and
    llm_agent.py/report_generation.py's fallback, gemini-1.5-flash, are both stale and do not
    reflect what's actually deployed locally).

.EXAMPLE
    ./register-fraud-agents-aws.ps1 -MeshBaseUrl "https://mesh.example.com" `
        -MeshAdminToken $env:MESH_ADMIN_TOKEN `
        -AgentPackagesDir "../Agent-mongo-fraud-agents/dist/agent-packages" `
        -AgentKeyVaultSigningKeyUri "arn:aws:kms:us-east-2:297784246949:key/..." `
        -GeminiApiKey $env:GEMINI_API_KEY
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "REQUIRED. Base URL of the AWS-deployed Mesh instance.")]
    [string]$MeshBaseUrl,

    [Parameter(Mandatory = $true, HelpMessage = "REQUIRED. A real admin-role Mesh bearer token. No default — never logged.")]
    [string]$MeshAdminToken,

    [Parameter(Mandatory = $true, HelpMessage = "REQUIRED. Directory containing the 4 agent TAR packages.")]
    [string]$AgentPackagesDir,

    [string]$ImageVersion = "latest",

    [Parameter(Mandatory = $true, HelpMessage = "REQUIRED. AWS KMS key ARN (or equivalent) used to verify agent assertions.")]
    [string]$AgentKeyVaultSigningKeyUri,

    [string]$AssertionAlgorithm = "RS256",

    # Must match deploy-fraud-detection-to-aws.ps1's -MongoDatabaseName (default fraud_detection_demo)
    # exactly. Agent-mongo-fraud-agents/aerospike_client/mongo_service.py defaults MONGODB_DATABASE
    # to "fraud_detection" when unset — a real live mismatch confirmed against the deployed
    # backend's own MONGODB_DATABASE=fraud_detection_demo env var: without this, agents write
    # investigation state (fraud_investigations collection) into a different database than the
    # backend reads from, so the pipeline reports success but the report never reaches the
    # frontend. ConnectionStrings__MongoDB alone is not enough — the database name segment in
    # that URI is overridden by MongoClient[MONGODB_DATABASE], not read from the URI path.
    [string]$MongoDatabaseName = "fraud_detection_demo",

    # Mesh's ContainerRuntime:Port config (appsettings.json, shared across every provider) is
    # 9090 -- confirmed live, not this project's own convention. EcsFargateContainerOrchestrator
    # maps the ECS container port to this value but never tells the AGENT what port to actually
    # listen on; this app's own SERVICE_PORT env var (default 8000, Python service/config.py)
    # must be set to match or the container comes up healthy on the wrong port and Mesh's
    # readiness probe never succeeds -- deploymentStatus sticks at Provisioning forever.
    [string]$AgentServicePort = "9090",

    # Matches docker-compose.split.yml's local Gemini E2E setup (Agent-mongo-fraud-agents repo) —
    # llm_agent.py / report_generation.py read LLM_PROVIDER (default "ollama" if unset), which is
    # unreachable from inside an ECS task with no local Ollama daemon. Default here to "gemini" so
    # cloud agents match the already-working local setup instead of falling back to Ollama.
    [string]$LlmProvider = "gemini",
    [string]$GeminiApiKey = $env:GEMINI_API_KEY,
    [string]$GeminiModel = "gemini-3.5-flash-lite"
)

if ($LlmProvider -eq "gemini" -and -not $GeminiApiKey) {
    throw "GeminiApiKey is required when LlmProvider is 'gemini' — pass -GeminiApiKey or set `$env:GEMINI_API_KEY."
}

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

$headers = @{ Authorization = "Bearer $MeshAdminToken" }

Write-Host "`n=== Uploading images and registering agents ===" -ForegroundColor Cyan
foreach ($agent in $Agents) {
    Write-Host "`n--- '$($agent.Id)' ---" -ForegroundColor Cyan

    # Direct upload: Mesh pushes the package's image into its own per-agent repository
    # (agents/<agentId>) and returns the digest-pinned imageReference that registration requires —
    # Mesh rejects any other repository or a bare tag (untrusted_container_image_reference).
    $tarPath = Join-Path $AgentPackagesDir "$($agent.Id).tar"
    $uploadUri = "$MeshBaseUrl/api/v1/admin/agents/$($agent.Id)/image?version=$([Uri]::EscapeDataString($ImageVersion))"
    try {
        $upload = Invoke-RestMethod -Uri $uploadUri -Method Post -Headers $headers -InFile $tarPath -ContentType "application/octet-stream"
    } catch {
        $responseBody = if ($_.ErrorDetails) { $_.ErrorDetails.Message } else { $null }
        throw "Image upload failed for '$($agent.Id)': $($_.Exception.Message)$(if ($responseBody) { " — $responseBody" })"
    }
    Write-Host "Uploaded image: $($upload.imageReference)" -ForegroundColor Green

    # Start from the package's own runtime-config.json (returned by the upload) rather than
    # assuming its shape — Build-AgentPackages.ps1 owns what goes in it. Mesh's Configuration is a
    # string-to-string map, so every value is sent as a string.
    $configuration = @{}
    if ($upload.runtimeConfig) {
        foreach ($prop in $upload.runtimeConfig.PSObject.Properties) { $configuration[$prop.Name] = [string]$prop.Value }
    }
    # SERVICE_PORT must match Mesh's own ContainerRuntime:Port (9090) — see -AgentServicePort.
    $configuration["SERVICE_PORT"] = [string]$AgentServicePort
    # NOTE: mesh_invocation_auth.py's Mesh endpoint URL is NOT set here on purpose. Mesh's own
    # ContainerDeploymentService.BuildEnvironmentVariables already auto-injects
    # "MeshAuth__EndpointUrl" (its own real base URL) into every ContainerInstance agent
    # unconditionally. Setting it again here previously caused a real bug: these keys get merged
    # into Mesh's own environment-variable dictionary case-INsensitively, so a same-named key here
    # (even with different casing) silently overwrote Mesh's own entry's VALUE while keeping ITS
    # casing on the wire.
    $configuration["MONGODB_DATABASE"] = $MongoDatabaseName
    $configuration["LLM_PROVIDER"] = $LlmProvider
    if ($LlmProvider -eq "gemini") {
        $configuration["GEMINI_API_KEY"] = $GeminiApiKey
        $configuration["GEMINI_MODEL"] = $GeminiModel
    }

    # KeyVaultSigningKeyUri is passed explicitly: Mesh only backfills it from runtime-config.json
    # onto an agent that already has a registration row.
    $body = @{
        agentId                     = $agent.Id
        name                        = $agent.Name
        description                 = $agent.Description
        registryAgentImageReference = $upload.imageReference
        configuration               = $configuration
        keyVaultSigningKeyUri       = $AgentKeyVaultSigningKeyUri
        assertionAlgorithm          = $AssertionAlgorithm
    } | ConvertTo-Json -Depth 10

    try {
        Invoke-RestMethod -Uri "$MeshBaseUrl/api/v1/admin/agents" -Method Post -Headers $headers -ContentType "application/json" -Body $body | Out-Null
        Write-Host "Registered (new) — deployment queued asynchronously." -ForegroundColor Green
    } catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        if ($statusCode -eq 409) {
            # Already registered (e.g. re-running this script to push a config change like
            # LLM_PROVIDER) — AdminController's POST is create-only; PUT is its update path.
            Invoke-RestMethod -Uri "$MeshBaseUrl/api/v1/admin/agents/$($agent.Id)" -Method Put -Headers $headers -ContentType "application/json" -Body $body | Out-Null
            Write-Host "Already registered — updated existing registration instead." -ForegroundColor Green
        } else {
            $responseBody = if ($_.ErrorDetails) { $_.ErrorDetails.Message } else { $null }
            throw "Failed to register '$($agent.Id)': $($_.Exception.Message)$(if ($responseBody) { " — $responseBody" })"
        }
    }
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
