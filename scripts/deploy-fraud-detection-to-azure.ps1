#Requires -Version 5.1
<#
.SYNOPSIS
    Deploy the fraud-detection demo's backend + frontend to Azure Container Apps (ACA),
    pointed at a cloud-deployed Mesh instance and a shared Mongo database.

.DESCRIPTION
    Builds both images in ACR (az acr build — no local docker daemon needed), creates two
    container apps (backend, frontend) in the given Container Apps Environment, seeds the shared
    Mongo database, and resets this demo's HITL policy entries to blocking — all scoped to
    exactly this demo (workflow/agent IDs tagged "fraud-detection-demo"), never a blanket write,
    since this Mesh deployment may be shared with other demos running their own workflows/agents
    in parallel at the same time (see reset_demo.py's module docstring for the full rationale).

    ACA (not ACI): gets HTTPS out of the box on the environment's default domain, matching how
    Mesh/Web are already deployed here — ACI's plain-HTTP FQDN would have made the Entra OAuth
    redirect URI (Workstream B) unworkable in most tenant configurations.

    Assumes the caller is already authenticated (`az login`, or `azure/login` in a GitHub Actions
    workflow) with RBAC in the target resource group and ACR — this script never calls `az login`
    itself, matching deploy-meshruntime-to-azure.ps1's convention.

.PARAMETER ResourceGroupName
    Azure Resource Group to deploy into. Default: rg-synchtrontrial-dev-eastus (same RG as
    Mesh/Web in this environment).

.PARAMETER ContainerAppsEnvironment
    Name of the existing Container Apps managed environment to deploy into. Default:
    acae-synchtrontrial-dev-eastus (the same environment Mesh/Web already run in).

.PARAMETER AcrName
    Azure Container Registry name (no .azurecr.io suffix). Default: synchtrontrialacrdeveastus
    (same ACR Mesh/Web already use).

.PARAMETER ImageTag
    Tag for both built images. Default: latest.

.PARAMETER MeshBaseUrl
    REQUIRED. Base URL of the cloud Mesh instance this demo talks to.

.PARAMETER MongoConnectionString
    REQUIRED. Connection string for the SHARED Mongo instance — the same one Mesh's own
    operational store uses. No default on purpose: an unset value must abort the deployment
    rather than silently falling back to something that could point at the wrong database.

.PARAMETER MongoDatabaseName
    Database name for this app's own data (users/accounts/flagged transactions) within the
    shared Mongo instance. Default: fraud_detection_demo.

.PARAMETER EntraTenantId
    REQUIRED. Entra tenant ID hosting both Mesh's and this demo's app registrations (the "same
    tenant as Mesh" requirement — real user login must validate against the same tenant/audience
    Mesh trusts).

.PARAMETER EntraClientId
    REQUIRED. Client ID of THIS demo's own Entra app registration (distinct from Mesh's or Web's).

.PARAMETER EntraClientSecret
    REQUIRED. Client secret for the above app registration. Never logged, never written to disk —
    passed as an ACA secret, referenced by env vars via secretref, not a literal env var value.

.PARAMETER SkipBuild
    Skip the az acr build steps and reuse whatever image already carries -ImageTag in the
    registry — use this to iterate on infra (env vars, container settings) without rebuilding.

.EXAMPLE
    ./deploy-fraud-detection-to-azure.ps1 `
        -MeshBaseUrl "https://synchtrontrial-mesh-dev-eastus.gentleisland-9bbb79b2.eastus.azurecontainerapps.io" `
        -MongoConnectionString $env:MESH_MONGO_CONNECTION_STRING `
        -EntraTenantId "320cb407-75c6-483d-965d-28454fbfc783" `
        -EntraClientId $env:FRAUD_DETECTION_CLIENT_ID `
        -EntraClientSecret $env:FRAUD_DETECTION_CLIENT_SECRET
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ResourceGroupName = "rg-synchtrontrial-dev-eastus",

    [Parameter(Mandatory = $false)]
    [string]$ContainerAppsEnvironment = "acae-synchtrontrial-dev-eastus",

    [Parameter(Mandatory = $false)]
    [string]$AcrName = "synchtrontrialacrdeveastus",

    [Parameter(Mandatory = $false)]
    [string]$ImageTag = "latest",

    [Parameter(Mandatory = $true, HelpMessage = "REQUIRED. Base URL of the cloud Mesh instance this demo talks to.")]
    [string]$MeshBaseUrl,

    [Parameter(Mandatory = $true, HelpMessage = "REQUIRED. Connection string for the shared Mongo instance (same one Mesh's operational store uses).")]
    [string]$MongoConnectionString,

    [Parameter(Mandatory = $false)]
    [string]$MongoDatabaseName = "fraud_detection_demo",

    [Parameter(Mandatory = $true, HelpMessage = "REQUIRED. Entra tenant ID hosting both Mesh's and this demo's app registrations.")]
    [string]$EntraTenantId,

    [Parameter(Mandatory = $true, HelpMessage = "REQUIRED. Client ID of this demo's own Entra app registration.")]
    [string]$EntraClientId,

    [Parameter(Mandatory = $true, HelpMessage = "REQUIRED. Client secret for this demo's Entra app registration.")]
    [string]$EntraClientSecret,

    [Parameter(Mandatory = $false)]
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")

$BackendImageName = "fraud-detection-backend"
$FrontendImageName = "fraud-detection-frontend"
$BackendAppName = "fraud-detection-backend"
$FrontendAppName = "fraud-detection-frontend"

$script:SecretValues = @($MongoConnectionString, $EntraClientSecret)

function Protect-LogLine {
    param([string]$Line)
    foreach ($secret in $script:SecretValues) {
        if ($secret) { $Line = $Line.Replace($secret, "***REDACTED***") }
    }
    return $Line
}

function Invoke-Az {
    param([string[]]$Arguments, [string]$ErrorContext, [string[]]$AdditionalSecrets = @())
    $allSecrets = $script:SecretValues + $AdditionalSecrets
    $displayLine = "`$ az $($Arguments -join ' ')"
    foreach ($secret in $allSecrets) {
        if ($secret) { $displayLine = $displayLine.Replace($secret, "***REDACTED***") }
    }
    Write-Host $displayLine -ForegroundColor Gray
    $output = & az @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host (Protect-LogLine ($output | Out-String)) -ForegroundColor Red
        throw "Failed: $ErrorContext (exit code $LASTEXITCODE)"
    }
    return $output
}

Write-Host "=== Verifying Azure login ===" -ForegroundColor Cyan
$account = az account show 2>$null | ConvertFrom-Json
if (-not $account) {
    throw "Not logged into Azure. Run 'az login' first (or ensure the calling workflow's azure/login step succeeded)."
}
Write-Host "Logged in as $($account.user.name), subscription $($account.name)" -ForegroundColor Green

if (-not $SkipBuild) {
    Write-Host "`n=== Building backend image in ACR ===" -ForegroundColor Cyan
    Invoke-Az -Arguments @(
        "acr", "build", "--registry", $AcrName,
        "--image", "${BackendImageName}:${ImageTag}",
        "--file", "backend.Dockerfile", "."
    ) -ErrorContext "az acr build (backend)" | Out-Null

    Write-Host "`n=== Building frontend image in ACR ===" -ForegroundColor Cyan
    Push-Location $RepoRoot
    try {
        Invoke-Az -Arguments @(
            "acr", "build", "--registry", $AcrName,
            "--image", "${FrontendImageName}:${ImageTag}",
            "--file", "frontend.Dockerfile", "."
        ) -ErrorContext "az acr build (frontend)" | Out-Null
    } finally {
        Pop-Location
    }
} else {
    Write-Host "`n=== Skipping image builds — reusing ${ImageTag} already in $AcrName ===" -ForegroundColor Yellow
}

Write-Host "`n=== Fetching ACR credentials ===" -ForegroundColor Cyan
# Ephemeral, in-memory only — never written to disk or echoed.
$acrCreds = Invoke-Az -Arguments @("acr", "credential", "show", "--name", $AcrName) -ErrorContext "az acr credential show" | ConvertFrom-Json
$acrLoginServer = "$AcrName.azurecr.io"
$acrPassword = $acrCreds.passwords[0].value

Write-Host "`n=== Removing any existing fraud-detection container apps ===" -ForegroundColor Cyan
foreach ($name in @($BackendAppName, $FrontendAppName)) {
    az containerapp show --resource-group $ResourceGroupName --name $name 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Removing existing container app '$name'..." -ForegroundColor Gray
        Invoke-Az -Arguments @("containerapp", "delete", "--resource-group", $ResourceGroupName, "--name", $name, "--yes") -ErrorContext "az containerapp delete ($name)" | Out-Null
    }
}

# ACA's external ingress FQDN is deterministic: <app-name>.<environment's default domain> —
# confirmed against Mesh's own FQDN (synchtrontrial-mesh-dev-eastus.<default-domain>). Computing
# both URLs upfront avoids a chicken-and-egg problem: the backend needs to know its OWN redirect
# URI (Workstream B) and the frontend's origin (CORS) at creation time, not after.
$EnvDefaultDomain = (Invoke-Az -Arguments @("containerapp", "env", "show", "--resource-group", $ResourceGroupName, "--name", $ContainerAppsEnvironment, "--query", "properties.defaultDomain", "-o", "tsv") -ErrorContext "containerapp env show (default domain)").Trim()
$backendUrl = "https://${BackendAppName}.${EnvDefaultDomain}"
$frontendUrl = "https://${FrontendAppName}.${EnvDefaultDomain}"
$redirectUri = "$backendUrl/auth/callback"
Write-Host "Backend will be at: $backendUrl" -ForegroundColor Gray
Write-Host "Frontend will be at: $frontendUrl" -ForegroundColor Gray

Write-Host "`n=== Deploying backend container app ===" -ForegroundColor Cyan
Invoke-Az -AdditionalSecrets @($acrPassword) -Arguments @(
    "containerapp", "create",
    "--resource-group", $ResourceGroupName,
    "--name", $BackendAppName,
    "--environment", $ContainerAppsEnvironment,
    "--image", "${acrLoginServer}/${BackendImageName}:${ImageTag}",
    "--registry-server", $acrLoginServer,
    "--registry-username", $acrCreds.username,
    "--registry-password", $acrPassword,
    "--target-port", "4000",
    "--ingress", "external",
    "--min-replicas", "1", "--max-replicas", "1",
    "--cpu", "1", "--memory", "2Gi",
    "--secrets",
        "mongo-connection-string=$MongoConnectionString",
        "entra-client-secret=$EntraClientSecret",
    "--env-vars",
        "MESH_BASE_URL=$MeshBaseUrl",
        "MONGODB_DATABASE=$MongoDatabaseName",
        "AZURE_TENANT_ID=$EntraTenantId",
        "AZURE_CLIENT_ID=$EntraClientId",
        "OAUTH_REDIRECT_URI=$redirectUri",
        "FRONTEND_ORIGIN=$frontendUrl",
        "MONGODB_CONNECTION_STRING=secretref:mongo-connection-string",
        "AZURE_CLIENT_SECRET=secretref:entra-client-secret"
) -ErrorContext "az containerapp create (backend)" | Out-Null

$backendFqdn = (Invoke-Az -Arguments @("containerapp", "show", "--resource-group", $ResourceGroupName, "--name", $BackendAppName, "--query", "properties.configuration.ingress.fqdn", "-o", "tsv") -ErrorContext "az containerapp show (backend fqdn)").Trim()
if ("https://$backendFqdn" -ne $backendUrl) {
    Write-Host "WARNING: actual backend FQDN (https://$backendFqdn) does not match the predicted URL ($backendUrl) — the redirect URI baked into this deployment is wrong. Investigate before testing login." -ForegroundColor Red
}
Write-Host "Backend deployed at $backendUrl" -ForegroundColor Green
Write-Host "Redirect URI this deployment will use: $redirectUri" -ForegroundColor Yellow
Write-Host "Confirm this exact URI is registered on the Entra app registration ($EntraClientId) before testing login." -ForegroundColor Yellow

Write-Host "`n=== Deploying frontend container app ===" -ForegroundColor Cyan
Invoke-Az -AdditionalSecrets @($acrPassword) -Arguments @(
    "containerapp", "create",
    "--resource-group", $ResourceGroupName,
    "--name", $FrontendAppName,
    "--environment", $ContainerAppsEnvironment,
    "--image", "${acrLoginServer}/${FrontendImageName}:${ImageTag}",
    "--registry-server", $acrLoginServer,
    "--registry-username", $acrCreds.username,
    "--registry-password", $acrPassword,
    "--target-port", "8080",
    "--ingress", "external",
    "--min-replicas", "1", "--max-replicas", "1",
    "--cpu", "1", "--memory", "2Gi",
    "--env-vars",
        "BACKEND_URL=$backendUrl",
        "NEXT_PUBLIC_BACKEND_URL=$backendUrl"
) -ErrorContext "az containerapp create (frontend)" | Out-Null

$frontendFqdn = (Invoke-Az -Arguments @("containerapp", "show", "--resource-group", $ResourceGroupName, "--name", $FrontendAppName, "--query", "properties.configuration.ingress.fqdn", "-o", "tsv") -ErrorContext "az containerapp show (frontend fqdn)").Trim()
if ("https://$frontendFqdn" -ne $frontendUrl) {
    Write-Host "WARNING: actual frontend FQDN (https://$frontendFqdn) does not match the predicted URL ($frontendUrl) used for the backend's CORS config." -ForegroundColor Red
}
Write-Host "Frontend deployed at $frontendUrl" -ForegroundColor Green

Write-Host "`n=== Seeding the shared Mongo database ===" -ForegroundColor Cyan
python3 (Join-Path $PSScriptRoot "seed_mongo.py") --mongo-uri $MongoConnectionString --db-name $MongoDatabaseName --clear
if ($LASTEXITCODE -ne 0) { throw "seed_mongo.py failed (exit code $LASTEXITCODE)" }

Write-Host "`n=== Clearing this demo's prior workflow manifests + HITL policy entries ===" -ForegroundColor Cyan
python3 (Join-Path $PSScriptRoot "reset_hitl_policy.py") --mesh-base-url $MeshBaseUrl --mesh-mongo-uri $MongoConnectionString
if ($LASTEXITCODE -ne 0) { throw "reset_hitl_policy.py failed (exit code $LASTEXITCODE)" }

Write-Host "`n✅ Fraud-detection demo deployed to Azure." -ForegroundColor Green
Write-Host "   Backend:  $backendUrl" -ForegroundColor Cyan
Write-Host "   Frontend: $frontendUrl" -ForegroundColor Cyan
Write-Host "   NOTE: /auth/login and /auth/callback are not implemented in the backend yet" -ForegroundColor Yellow
Write-Host "   (Workstream B) — until then, Mesh calls from this deployment will fail, since" -ForegroundColor Yellow
Write-Host "   /local/token is Production-only-disabled on cloud Mesh." -ForegroundColor Yellow
