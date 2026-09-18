#Requires -Version 5.1
<#
.SYNOPSIS
    Tear down the fraud-detection demo's Azure resources: both ACA container apps, this
    demo's tagged entries in Mesh's HITL policy, and the entire fraud_detection_demo database.

.DESCRIPTION
    Deletes the backend + frontend container apps, scrubs this demo's workflow/agent
    entries out of Mesh's shared HITL policy document (tag-scoped — see
    deploy-fraud-detection-to-azure.ps1 and reset_hitl_policy.py for why this is never a blanket
    write against a Mesh deployment other demos may share), and drops the fraud_detection_demo
    database wholesale from the shared Mongo instance — safe, since that database is fully owned
    by this app and nothing else reads it (unlike Mesh's own operational-store database in the
    same instance, which this script never touches beyond the tag-scoped policy scrub).

    Assumes the caller is already authenticated (`az login`, or `azure/login` in a GitHub Actions
    workflow) — this script never calls `az login` itself.

.PARAMETER ResourceGroupName
    Azure Resource Group the container apps live in. Default: rg-synchtrontrial-dev-eastus.

.PARAMETER MeshBaseUrl
    REQUIRED. Base URL of the cloud Mesh instance this demo's HITL policy entries live in.

.PARAMETER MongoConnectionString
    REQUIRED. Connection string for the shared Mongo instance (used both to drop
    fraud_detection_demo and, via reset_hitl_policy.py, to find this demo's tagged workflow
    manifests in Mesh's own operational-store database within that same instance).

.PARAMETER MongoDatabaseName
    Database name to drop. Default: fraud_detection_demo.

.EXAMPLE
    ./teardown-fraud-detection-azure.ps1 `
        -MeshBaseUrl "https://synchtrontrial-mesh-dev-eastus.gentleisland-9bbb79b2.eastus.azurecontainerapps.io" `
        -MongoConnectionString $env:MESH_MONGO_CONNECTION_STRING
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ResourceGroupName = "rg-synchtrontrial-dev-eastus",

    [Parameter(Mandatory = $true, HelpMessage = "REQUIRED. Base URL of the cloud Mesh instance this demo's HITL policy entries live in.")]
    [string]$MeshBaseUrl,

    [Parameter(Mandatory = $true, HelpMessage = "REQUIRED. Connection string for the shared Mongo instance.")]
    [string]$MongoConnectionString,

    [Parameter(Mandatory = $false)]
    [string]$MongoDatabaseName = "fraud_detection_demo"
)

$ErrorActionPreference = "Stop"

$BackendAppName = "fraud-detection-backend"
$FrontendAppName = "fraud-detection-frontend"

Write-Host "=== Verifying Azure login ===" -ForegroundColor Cyan
$account = az account show 2>$null | ConvertFrom-Json
if (-not $account) {
    throw "Not logged into Azure. Run 'az login' first (or ensure the calling workflow's azure/login step succeeded)."
}
Write-Host "Logged in as $($account.user.name), subscription $($account.name)" -ForegroundColor Green

Write-Host "`n=== Deleting container apps ===" -ForegroundColor Cyan
foreach ($name in @($BackendAppName, $FrontendAppName)) {
    az containerapp show --resource-group $ResourceGroupName --name $name 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Deleting '$name'..." -ForegroundColor Gray
        az containerapp delete --resource-group $ResourceGroupName --name $name --yes 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Failed to delete container app '$name'" }
    } else {
        Write-Host "'$name' does not exist — skipping." -ForegroundColor Gray
    }
}
Write-Host "Both container apps removed (or already absent)." -ForegroundColor Green

Write-Host "`n=== Clearing this demo's workflow manifests + HITL policy entries ===" -ForegroundColor Cyan
python3 (Join-Path $PSScriptRoot "reset_hitl_policy.py") --mesh-base-url $MeshBaseUrl --mesh-mongo-uri $MongoConnectionString
if ($LASTEXITCODE -ne 0) {
    Write-Host "WARNING: HITL policy cleanup failed — continuing with database drop anyway (see output above)." -ForegroundColor Yellow
}

Write-Host "`n=== Dropping the $MongoDatabaseName database ===" -ForegroundColor Cyan
# Passed via environment variable, not string-interpolated into the script body — avoids any
# quoting hazard from special characters in the connection string (and keeps it out of process
# listings, since it's read from the environment rather than a CLI argument).
$env:TEARDOWN_MONGO_URI = $MongoConnectionString
$env:TEARDOWN_DB_NAME = $MongoDatabaseName
$dropScript = @"
import os
from pymongo import MongoClient
c = MongoClient(os.environ['TEARDOWN_MONGO_URI'])
db_name = os.environ['TEARDOWN_DB_NAME']
c.drop_database(db_name)
print(f'Dropped database {db_name}')
"@
$dropScript | python3 -
$dropExitCode = $LASTEXITCODE
Remove-Item Env:\TEARDOWN_MONGO_URI, Env:\TEARDOWN_DB_NAME -ErrorAction SilentlyContinue
if ($dropExitCode -ne 0) { throw "Failed to drop database '$MongoDatabaseName'" }

Write-Host "`n✅ Fraud-detection demo torn down — container apps removed, HITL policy entries scrubbed, database dropped." -ForegroundColor Green
