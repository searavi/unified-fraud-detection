#Requires -Version 7.0
<#
.SYNOPSIS
    Resets the AWS-deployed fraud-detection demo's HITL state so the next investigation is blocked
    again and the UI shows "Enable workflow execution".

.DESCRIPTION
    Runs the same cleanup deploy-fraud-detection-to-aws.ps1 runs as its final step —
    scripts/reset_hitl_policy.py with --mesh-mongo-uri — as a one-off ECS task on the backend's own
    task definition (Mesh's Mongo is only reachable from inside the VPC). That removes this demo's
    4 agent IDs and its workflow IDs from Mesh's HITL policy document and deletes this demo's
    tagged workflow manifests; entries belonging to other demos sharing the Mesh are left alone.

    Because the manifest the running backend has cached is deleted, the backend service is then
    force-redeployed so it registers a fresh workflow on the next investigation.

    Demo data in Mongo (seeded alerts, past investigations) is NOT touched — re-run
    deploy-fraud-detection-to-aws.ps1 for a full reseed.

    The Mongo connection string is read from the backend's own task definition and the Mesh admin
    token is minted for the automation user (same as deploy-fraud-detection-to-aws.ps1); neither
    is ever printed.

.PARAMETER MeshBaseUrl
    REQUIRED. Base URL of the AWS-deployed Mesh instance.

.EXAMPLE
    ./reset-demo-aws.ps1 -MeshBaseUrl "https://mesh.example.com"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "REQUIRED. Base URL of the AWS-deployed Mesh instance.")]
    [string]$MeshBaseUrl,

    [string]$Region = "us-east-2",
    [string]$ClusterName = "fraud-detection-dev-useast2",
    [string]$BackendServiceName = "fraud-detection-backend",

    # Must match deploy-fraud-detection-to-aws.ps1's defaults.
    [string]$AutomationUsername = "fraud-detection-automation@synchtron-test.local",
    [string]$AutomationSecretName = "fraud-detection/dev/automation-user-password",
    [string]$MeshAdminClientId = "2fvmn3og01l444d57fbojla6k6"
)

$ErrorActionPreference = "Stop"

function Get-MeshAdminToken {
    $password = aws secretsmanager get-secret-value --region $Region --secret-id $AutomationSecretName --query "SecretString" --output text 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $password) { throw "Failed to fetch '$AutomationUsername' password from Secrets Manager ($AutomationSecretName)." }
    $authResult = aws cognito-idp initiate-auth --region $Region --client-id $MeshAdminClientId --auth-flow USER_PASSWORD_AUTH `
        --auth-parameters "USERNAME=$AutomationUsername,PASSWORD=$password" 2>$null
    if ($LASTEXITCODE -ne 0) { throw "initiate-auth failed for '$AutomationUsername' (exit code $LASTEXITCODE)." }
    $idToken = ($authResult | ConvertFrom-Json).AuthenticationResult.IdToken
    if (-not $idToken) { throw "initiate-auth succeeded but returned no IdToken for '$AutomationUsername'." }
    return $idToken
}

Write-Host "=== Reading backend service configuration ===" -ForegroundColor Cyan
$service = (aws ecs describe-services --region $Region --cluster $ClusterName --services $BackendServiceName --output json | ConvertFrom-Json).services[0]
if (-not $service) { throw "ECS service '$BackendServiceName' not found in cluster '$ClusterName'." }
$taskDefinition = $service.taskDefinition
$vpcConfig = $service.networkConfiguration.awsvpcConfiguration

$mongoQuery = "taskDefinition.containerDefinitions[0].environment[?name=='MONGODB_CONNECTION_STRING'].value | [0]"
$mongoConnectionString = aws ecs describe-task-definition --region $Region --task-definition $taskDefinition --query $mongoQuery --output text
if (-not $mongoConnectionString -or $mongoConnectionString -eq "None") { throw "MONGODB_CONNECTION_STRING not found on $taskDefinition." }

$meshAdminToken = Get-MeshAdminToken

Write-Host "`n=== Clearing this demo's workflow manifests + HITL policy entries ===" -ForegroundColor Cyan
$overrides = @{
    containerOverrides = @(@{
        name    = $BackendServiceName
        command = @("python3", "scripts/reset_hitl_policy.py", "--mesh-base-url", $MeshBaseUrl,
                    "--mesh-mongo-uri", $mongoConnectionString, "--mesh-admin-token", $meshAdminToken)
    })
} | ConvertTo-Json -Depth 10
$tmpOverrides = New-TemporaryFile
try {
    Set-Content -Path $tmpOverrides -Value $overrides -NoNewline
    $networkConfig = "awsvpcConfiguration={subnets=[$($vpcConfig.subnets -join ',')],securityGroups=[$($vpcConfig.securityGroups -join ',')],assignPublicIp=$($vpcConfig.assignPublicIp)}"
    $taskArn = aws ecs run-task --region $Region --cluster $ClusterName --task-definition $taskDefinition --launch-type FARGATE `
        --network-configuration $networkConfig --overrides "file://$tmpOverrides" --query "tasks[0].taskArn" --output text 2>$null
} finally {
    Remove-Item $tmpOverrides -ErrorAction SilentlyContinue
}
if ($LASTEXITCODE -ne 0 -or -not $taskArn -or $taskArn -eq "None") { throw "ecs run-task failed for the reset task." }

aws ecs wait tasks-stopped --region $Region --cluster $ClusterName --tasks $taskArn
$exitCode = aws ecs describe-tasks --region $Region --cluster $ClusterName --tasks $taskArn --query "tasks[0].containers[0].exitCode" --output text
if ($exitCode -ne "0") {
    throw "Reset task failed (container exit code $exitCode). Check CloudWatch log group /ecs/$BackendServiceName (task ARN: $taskArn)."
}
Write-Host "Reset completed successfully." -ForegroundColor Green

Write-Host "`n=== Restarting the backend so it registers a fresh workflow ===" -ForegroundColor Cyan
aws ecs update-service --region $Region --cluster $ClusterName --service $BackendServiceName --force-new-deployment | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Failed to force a new deployment of '$BackendServiceName'." }
aws ecs wait services-stable --region $Region --cluster $ClusterName --services $BackendServiceName
if ($LASTEXITCODE -ne 0) { throw "'$BackendServiceName' did not stabilize after the restart." }

Write-Host "`n✅ Demo reset. The next investigation will stop at the HITL gate and offer 'Enable workflow execution'." -ForegroundColor Green
