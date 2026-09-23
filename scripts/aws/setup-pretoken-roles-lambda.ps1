#Requires -Version 5.1
<#
.SYNOPSIS
    Attaches (or, with -Rollback, detaches) a Pre Token Generation Lambda trigger on the SHARED
    Mesh admin app client's Cognito user pool that adds a "roles" claim derived from
    cognito:groups membership to the ID token.

    Why: Mesh's own authorization code (AdminRoleAuthorizationHandler for AdminPolicy,
    WorkflowController.ExtractHitlContextFromClaims for HITL/OPA Gate 3) reads roles from a
    claim literally named "roles" only — Cognito never emits one natively, only
    "cognito:groups". Without this, no Cognito-authenticated caller can ever be recognized as
    an executor/admin, regardless of policy content. See src/Synktron.MeshRuntime.Service/
    Authorization/AdminRoleAuthorizationHandler.cs and Controllers/WorkflowController.cs
    (ExtractHitlContextFromClaims) in the Mesh repo for the exact read sites this bridges.

    THIS TOUCHES A SHARED POOL: the same user pool backs Mesh's own real user login, not just
    this demo. Safety properties, all load-bearing, do not weaken them:
      - The Lambda itself (lambda/pretoken-roles/index.mjs) is additive-only and fail-open: it
        only ever ADDS a "roles" claim, never suppresses/overrides anything else, and any
        internal error is swallowed so login always proceeds unmodified.
      - UpdateUserPool is a FULL-REPLACE API (AWS's own docs: "If you don't provide a value for
        an attribute, Amazon Cognito sets it to its default value") — every call here fetches
        the pool's CURRENT full configuration and resends it verbatim, changing only
        LambdaConfig.PreTokenGeneration, exactly like the CallbackURLs fix in
        deploy-fraud-detection-to-aws.ps1 for UpdateUserPoolClient.
      - -Rollback restores the exact LambdaConfig captured before this script's first run
        (backup JSON on disk) — a full config, not a delta — and does not delete the Lambda
        function/IAM role by default, since detaching the trigger alone is what stops it from
        running; deletion is opt-in via -DeleteLambdaResources.

.PARAMETER UserPoolId
    Mesh's shared Cognito user pool. Default matches the pool ID already used by
    setup-fraud-detection-iam.ps1 / deploy-fraud-detection-to-aws.ps1.

.PARAMETER Region
    AWS region. Default: us-east-2 (matches sibling scripts).

.PARAMETER Rollback
    Restores the LambdaConfig captured in the backup file instead of applying the trigger.

.PARAMETER BackupPath
    Where the pre-change LambdaConfig snapshot is written (setup) / read from (-Rollback).
    Default: alongside this script.

.PARAMETER DeleteLambdaResources
    Only meaningful with -Rollback. Also deletes the Lambda function, its invoke permission, and
    its execution role. Off by default — leaving the (now-detached, inert) function in place is
    strictly safer than a delete that could fail partway.
#>
[CmdletBinding()]
param(
    [string]$UserPoolId = "us-east-2_D0FCCAyEB",
    [string]$Region = "us-east-2",
    [switch]$Rollback,
    [string]$BackupPath = "$PSScriptRoot/pretoken-roles-lambda-config-backup.json",
    [switch]$DeleteLambdaResources
)

$ErrorActionPreference = "Stop"

$FunctionName = "fraud-detection-pretoken-roles"
$RoleName = "fraud-detection-pretoken-roles-lambda-role"
$LambdaSourceDir = "$PSScriptRoot/lambda/pretoken-roles"
$PermissionStatementId = "AllowCognitoInvokePretokenRoles"

function Invoke-Aws {
    param([string[]]$Arguments, [string]$ErrorContext)
    Write-Host "`$ aws $($Arguments -join ' ')" -ForegroundColor Gray
    $output = & aws @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host ($output | Out-String) -ForegroundColor Red
        throw "Failed: $ErrorContext (exit code $LASTEXITCODE)"
    }
    return $output
}

function Get-UserPoolFull {
    $json = Invoke-Aws -Arguments @("cognito-idp", "describe-user-pool", "--user-pool-id", $UserPoolId, "--region", $Region) `
        -ErrorContext "describe-user-pool $UserPoolId"
    return ($json | Out-String | ConvertFrom-Json).UserPool
}

# UpdateUserPool full-replace safety: project the DescribeUserPool response down to exactly the
# fields UpdateUserPool accepts (renaming Name -> PoolName, dropping read-only/immutable fields
# like Id/Arn/CreationDate/SchemaAttributes/AliasAttributes/UsernameAttributes/Domain that
# UpdateUserPool does not accept), and swap in the desired LambdaConfig. Every other setting
# (Policies, MFA, email/SMS config, tags, etc.) passes through unchanged.
function Build-UpdatePayload {
    param($CurrentPool, $NewLambdaConfig)

    $payload = [ordered]@{
        UserPoolId = $UserPoolId
        PoolName   = $CurrentPool.Name
    }
    $passthroughFields = @(
        "Policies", "DeletionProtection", "AutoVerifiedAttributes", "DeviceConfiguration",
        "EmailConfiguration", "MfaConfiguration", "SmsConfiguration", "UserPoolAddOns",
        "UserPoolTags", "UserPoolTier", "VerificationMessageTemplate",
        "UserAttributeUpdateSettings", "AccountRecoverySetting", "AdminCreateUserConfig",
        "IssuerConfiguration", "KeyConfiguration"
    )
    foreach ($field in $passthroughFields) {
        $value = $CurrentPool.$field
        if ($null -ne $value) { $payload[$field] = $value }
    }
    $payload["LambdaConfig"] = $NewLambdaConfig
    return $payload
}

function Set-UserPoolLambdaConfig {
    param($NewLambdaConfig)
    $current = Get-UserPoolFull
    $payload = Build-UpdatePayload -CurrentPool $current -NewLambdaConfig $NewLambdaConfig
    $tmpFile = New-TemporaryFile
    try {
        ($payload | ConvertTo-Json -Depth 20) | Set-Content -Path $tmpFile -Encoding utf8
        Invoke-Aws -Arguments @("cognito-idp", "update-user-pool", "--region", $Region, "--cli-input-json", "file://$tmpFile") `
            -ErrorContext "update-user-pool $UserPoolId (LambdaConfig)" | Out-Null
    }
    finally {
        Remove-Item $tmpFile -ErrorAction SilentlyContinue
    }
}

if ($Rollback) {
    Write-Host "=== Rolling back Pre Token Generation trigger on $UserPoolId ===" -ForegroundColor Cyan
    if (-not (Test-Path $BackupPath)) {
        throw "No backup found at $BackupPath — nothing to roll back to. If the trigger was never applied, there's nothing to do."
    }
    $backup = Get-Content $BackupPath -Raw | ConvertFrom-Json
    $originalLambdaConfig = $backup.LambdaConfig
    if ($null -eq $originalLambdaConfig) { $originalLambdaConfig = @{} }

    Write-Host "Restoring original LambdaConfig: $($originalLambdaConfig | ConvertTo-Json -Compress)" -ForegroundColor Yellow
    Set-UserPoolLambdaConfig -NewLambdaConfig $originalLambdaConfig
    Write-Host "Restored. Log in again and confirm behavior matches pre-change state." -ForegroundColor Green

    if ($DeleteLambdaResources) {
        Write-Host "`n=== Deleting Lambda resources ===" -ForegroundColor Cyan
        try {
            Invoke-Aws -Arguments @("lambda", "delete-function", "--function-name", $FunctionName, "--region", $Region) `
                -ErrorContext "delete-function $FunctionName" | Out-Null
        } catch { Write-Host "Function delete skipped/failed (may not exist): $_" -ForegroundColor Yellow }
        try {
            Invoke-Aws -Arguments @("iam", "delete-role-policy", "--role-name", $RoleName, "--policy-name", "AWSLambdaBasicExecutionRole-inline") `
                -ErrorContext "delete-role-policy $RoleName" | Out-Null
        } catch { }
        try {
            Invoke-Aws -Arguments @("iam", "detach-role-policy", "--role-name", $RoleName, "--policy-arn", "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole") `
                -ErrorContext "detach-role-policy $RoleName" | Out-Null
        } catch { }
        try {
            Invoke-Aws -Arguments @("iam", "delete-role", "--role-name", $RoleName) -ErrorContext "delete-role $RoleName" | Out-Null
        } catch { Write-Host "Role delete skipped/failed (may not exist): $_" -ForegroundColor Yellow }
    }
    Write-Host "`nDone." -ForegroundColor Green
    return
}

Write-Host "=== Verifying AWS login ===" -ForegroundColor Cyan
$callerIdentity = aws sts get-caller-identity 2>$null | ConvertFrom-Json
if (-not $callerIdentity) { throw "Not logged into AWS. Run your SSO login first." }
$AccountId = $callerIdentity.Account
Write-Host "Account: $AccountId, region: $Region" -ForegroundColor Green

Write-Host "`n=== Backing up current LambdaConfig before touching anything ===" -ForegroundColor Cyan
$currentPool = Get-UserPoolFull
$currentLambdaConfig = $currentPool.LambdaConfig
if ($null -eq $currentLambdaConfig) { $currentLambdaConfig = [ordered]@{} }
@{ LambdaConfig = $currentLambdaConfig; CapturedAtUtc = [DateTime]::UtcNow.ToString("o") } |
    ConvertTo-Json -Depth 20 | Set-Content -Path $BackupPath -Encoding utf8
Write-Host "Backed up to $BackupPath — run this script with -Rollback to restore it." -ForegroundColor Green

Write-Host "`n=== Creating/updating IAM execution role ===" -ForegroundColor Cyan
$roleExists = $true
try { Invoke-Aws -Arguments @("iam", "get-role", "--role-name", $RoleName) -ErrorContext "get-role $RoleName" | Out-Null }
catch { $roleExists = $false }

if (-not $roleExists) {
    $trustPolicy = @{
        Version   = "2012-10-17"
        Statement = @(@{ Effect = "Allow"; Principal = @{ Service = "lambda.amazonaws.com" }; Action = "sts:AssumeRole" })
    } | ConvertTo-Json -Depth 10
    $trustFile = New-TemporaryFile
    $trustPolicy | Set-Content -Path $trustFile -Encoding utf8
    Invoke-Aws -Arguments @("iam", "create-role", "--role-name", $RoleName, "--assume-role-policy-document", "file://$trustFile") `
        -ErrorContext "create-role $RoleName" | Out-Null
    Remove-Item $trustFile -ErrorAction SilentlyContinue
    Invoke-Aws -Arguments @("iam", "attach-role-policy", "--role-name", $RoleName, "--policy-arn", "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole") `
        -ErrorContext "attach-role-policy $RoleName" | Out-Null
    Write-Host "Created role $RoleName. Waiting for IAM propagation..." -ForegroundColor Yellow
    Start-Sleep -Seconds 10
} else {
    Write-Host "Role $RoleName already exists, reusing." -ForegroundColor Green
}
$roleArn = "arn:aws:iam::${AccountId}:role/$RoleName"

Write-Host "`n=== Packaging Lambda code ===" -ForegroundColor Cyan
$zipPath = Join-Path ([System.IO.Path]::GetTempPath()) "pretoken-roles-$([Guid]::NewGuid().ToString('N')).zip"
Compress-Archive -Path "$LambdaSourceDir/index.mjs" -DestinationPath $zipPath -Force
Write-Host "Packaged $LambdaSourceDir/index.mjs -> $zipPath" -ForegroundColor Green

Write-Host "`n=== Creating/updating Lambda function ===" -ForegroundColor Cyan
$functionExists = $true
try { Invoke-Aws -Arguments @("lambda", "get-function", "--function-name", $FunctionName, "--region", $Region) -ErrorContext "get-function $FunctionName" | Out-Null }
catch { $functionExists = $false }

if ($functionExists) {
    Invoke-Aws -Arguments @("lambda", "update-function-code", "--function-name", $FunctionName, "--zip-file", "fileb://$zipPath", "--region", $Region) `
        -ErrorContext "update-function-code $FunctionName" | Out-Null
} else {
    Invoke-Aws -Arguments @(
        "lambda", "create-function", "--function-name", $FunctionName,
        "--runtime", "nodejs20.x", "--handler", "index.handler", "--role", $roleArn,
        "--zip-file", "fileb://$zipPath", "--timeout", "5", "--memory-size", "128", "--region", $Region
    ) -ErrorContext "create-function $FunctionName" | Out-Null
}
Remove-Item $zipPath -ErrorAction SilentlyContinue
$lambdaArn = "arn:aws:lambda:${Region}:${AccountId}:function:$FunctionName"
Write-Host "Lambda ready: $lambdaArn" -ForegroundColor Green

Write-Host "`n=== Granting Cognito permission to invoke it ===" -ForegroundColor Cyan
try {
    Invoke-Aws -Arguments @(
        "lambda", "add-permission", "--function-name", $FunctionName, "--statement-id", $PermissionStatementId,
        "--action", "lambda:InvokeFunction", "--principal", "cognito-idp.amazonaws.com",
        "--source-arn", "arn:aws:cognito-idp:${Region}:${AccountId}:userpool/$UserPoolId", "--region", $Region
    ) -ErrorContext "add-permission $FunctionName" | Out-Null
} catch {
    if ($_.Exception.Message -match "ResourceConflictException") {
        Write-Host "Permission already granted, skipping." -ForegroundColor Green
    } else { throw }
}

Write-Host "`n=== Attaching trigger to user pool (additive: only LambdaConfig.PreTokenGeneration changes) ===" -ForegroundColor Cyan
$newLambdaConfig = [ordered]@{}
foreach ($prop in $currentLambdaConfig.PSObject.Properties) { $newLambdaConfig[$prop.Name] = $prop.Value }
$newLambdaConfig["PreTokenGeneration"] = $lambdaArn
Set-UserPoolLambdaConfig -NewLambdaConfig $newLambdaConfig

Write-Host "`n=== Done ===" -ForegroundColor Green
Write-Host "Validate before relying on this:" -ForegroundColor Yellow
Write-Host "  1. Log in again through the fraud-detection frontend as a mesh-admins member." -ForegroundColor Yellow
Write-Host "  2. Decode the resulting ID token (jwt.io or similar) and confirm it now has BOTH" -ForegroundColor Yellow
Write-Host "     'cognito:groups' (unchanged) AND a new 'roles' claim = mesh.admin." -ForegroundColor Yellow
Write-Host "  3. Log in as a user NOT in mesh-admins and confirm login still succeeds (no roles claim, that's expected)." -ForegroundColor Yellow
Write-Host "  4. Retry the HITL 'Enable Workflow Execution' -> 'Start AI Investigation' flow end to end." -ForegroundColor Yellow
Write-Host "If ANY login breaks: run this script again with -Rollback to restore the pool's prior LambdaConfig immediately." -ForegroundColor Yellow
