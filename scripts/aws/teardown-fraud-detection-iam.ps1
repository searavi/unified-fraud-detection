#Requires -Version 5.1
<#
.SYNOPSIS
    Reverses setup-fraud-detection-iam.ps1's KMS provisioning: schedules deletion of the
    dedicated fraud-detection agent signing key, removes its alias, and removes the
    fraud-detection-only statement this script's setup counterpart added to Mesh's own task
    role's 'kms-sign' policy (leaving that policy's pre-existing statement for Mesh's shared
    OAuth-signing key untouched).

.DESCRIPTION
    Only decommissions the AGENT SIGNING KEY material — NOT the GitHub Actions OIDC deployer
    role setup-fraud-detection-iam.ps1 also creates, since that role is meant to persist across
    many demo up/down cycles and removing it would break future CI deploys. Pass
    -DeleteGitHubActionsRole explicitly if you really are decommissioning the whole fraud-
    detection AWS setup, not just its agent-signing key.

    Run this only once you're certain no fraud-detection agents are still registered against
    the key being deleted — run unregister-fraud-agents-aws.ps1 first. KMS key deletion has a
    mandatory pending window (AWS minimum 7 days) during which the key still exists but is
    disabled for use; it is NOT instantly and irreversibly gone.

.PARAMETER PendingWindowInDays
    KMS deletion pending window, 7-30 days per AWS. Default: 7 (the minimum) — this is a dev key.

.PARAMETER DeleteGitHubActionsRole
    Also deletes the GitHub Actions OIDC deployer role and its policy. Off by default.

.EXAMPLE
    ./teardown-fraud-detection-iam.ps1
.EXAMPLE
    ./teardown-fraud-detection-iam.ps1 -DeleteGitHubActionsRole
#>

[CmdletBinding()]
param(
    [string]$Region = "us-east-2",
    [string]$KmsAliasName = "alias/fraud-detection-agent-signing-dev",
    [string]$MeshTaskRoleName = "role-synchtron-mesh-task-dev-useast2",
    [int]$PendingWindowInDays = 7,

    [switch]$DeleteGitHubActionsRole,
    [string]$RoleName = "role-fraud-detection-github-actions-dev",
    [string]$PolicyName = "FraudDetectionDeployer"
)

$ErrorActionPreference = "Stop"

$account = aws sts get-caller-identity | ConvertFrom-Json
if (-not $account) { throw "Not logged into AWS. Run 'aws login' (or your account's SSO equivalent) first." }
$accountId = $account.Account
Write-Host "Account: $accountId" -ForegroundColor Green

Write-Host "`n=== Removing Mesh task role's grant on the fraud-detection signing key ===" -ForegroundColor Cyan
$meshFraudSid = "VerifyFraudDetectionAgentAssertions"
$existingMeshPolicyJson = (aws iam get-role-policy --role-name $MeshTaskRoleName --policy-name kms-sign --query "PolicyDocument" --output json 2>$null)
if ($LASTEXITCODE -eq 0 -and $existingMeshPolicyJson) {
    $meshPolicyObj = $existingMeshPolicyJson | ConvertFrom-Json
    $remainingStatements = @($meshPolicyObj.Statement | Where-Object { $_.Sid -ne $meshFraudSid })
    if ($remainingStatements.Count -eq $meshPolicyObj.Statement.Count) {
        Write-Host "'$MeshTaskRoleName' kms-sign policy has no '$meshFraudSid' statement — nothing to remove." -ForegroundColor Yellow
    } elseif ($remainingStatements.Count -eq 0) {
        Write-Host "Removing 'kms-sign' policy from '$MeshTaskRoleName' entirely (no other statements left)." -ForegroundColor Yellow
        aws iam delete-role-policy --role-name $MeshTaskRoleName --policy-name kms-sign
        if ($LASTEXITCODE -ne 0) { throw "Failed to delete now-empty 'kms-sign' policy from '$MeshTaskRoleName'" }
    } else {
        $meshPolicy = @{ Version = "2012-10-17"; Statement = $remainingStatements } | ConvertTo-Json -Depth 10
        $tmpMeshPolicy = New-TemporaryFile
        Set-Content -Path $tmpMeshPolicy -Value $meshPolicy -NoNewline
        try {
            aws iam put-role-policy --role-name $MeshTaskRoleName --policy-name kms-sign --policy-document "file://$tmpMeshPolicy"
            if ($LASTEXITCODE -ne 0) { throw "Failed to update '$MeshTaskRoleName' kms-sign policy" }
        } finally {
            Remove-Item $tmpMeshPolicy -ErrorAction SilentlyContinue
        }
        Write-Host "Removed the fraud-detection statement; Mesh's shared-key grant left untouched." -ForegroundColor Green
    }
} else {
    Write-Host "'$MeshTaskRoleName' has no 'kms-sign' policy at all — nothing to remove." -ForegroundColor Yellow
}

Write-Host "`n=== Scheduling deletion of the fraud-detection signing key ===" -ForegroundColor Cyan
$keyId = (aws kms describe-key --key-id $KmsAliasName --region $Region --query "KeyMetadata.KeyId" --output text 2>$null)
if ($LASTEXITCODE -ne 0 -or -not $keyId) {
    Write-Host "No KMS key found under alias '$KmsAliasName' — nothing to delete." -ForegroundColor Yellow
} else {
    $keyId = $keyId.Trim()

    aws kms delete-alias --alias-name $KmsAliasName --region $Region
    if ($LASTEXITCODE -ne 0) { throw "Failed to delete alias '$KmsAliasName'" }
    Write-Host "Alias '$KmsAliasName' deleted." -ForegroundColor Green

    aws kms schedule-key-deletion --key-id $keyId --pending-window-in-days $PendingWindowInDays --region $Region | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to schedule deletion for key $keyId" }
    Write-Host "Key $keyId scheduled for deletion in $PendingWindowInDays day(s) — disabled immediately, fully gone after the window." -ForegroundColor Green
}

if ($DeleteGitHubActionsRole) {
    Write-Host "`n=== Deleting GitHub Actions deployer role ===" -ForegroundColor Cyan
    aws iam get-role --role-name $RoleName 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) {
        aws iam delete-role-policy --role-name $RoleName --policy-name $PolicyName
        if ($LASTEXITCODE -ne 0) { throw "Failed to delete policy '$PolicyName' from '$RoleName'" }
        aws iam delete-role --role-name $RoleName
        if ($LASTEXITCODE -ne 0) { throw "Failed to delete role '$RoleName'" }
        Write-Host "Role '$RoleName' deleted." -ForegroundColor Green
    } else {
        Write-Host "Role '$RoleName' does not exist — nothing to delete." -ForegroundColor Yellow
    }
} else {
    Write-Host "`nGitHub Actions deployer role left in place (pass -DeleteGitHubActionsRole to remove it too)." -ForegroundColor Gray
}

Write-Host "`n✅ Fraud-detection IAM/KMS teardown complete." -ForegroundColor Green
