#Requires -Version 5.1
<#
.SYNOPSIS
    Tear down the fraud-detection demo's AWS resources: ECS services/cluster, ALB + target
    groups, the ECR repositories (backend/frontend images), the security groups (including the
    ingress rule granted on Mesh's Mongo security group), the Cognito app client, the Secrets
    Manager secret, this demo's tagged entries in Mesh's HITL policy, and the entire
    fraud_detection_demo database.

.DESCRIPTION
    Deletes only resources this demo's own deploy script created — never touches Mesh's own
    ECS cluster, Cognito user pool, or Mongo EC2 instance beyond revoking the one ingress rule
    granted to fraud-detection's task security group.

    Assumes the caller is already authenticated (`aws sts get-caller-identity` succeeds).

.PARAMETER Region
    Default: us-east-2.

.PARAMETER ClusterName
    Default: fraud-detection-dev-useast2.

.PARAMETER MeshBaseUrl
    REQUIRED. Base URL of the AWS-deployed Mesh instance this demo's HITL policy entries live in.

.PARAMETER MongoConnectionString
    REQUIRED. Connection string for the shared Mongo instance. No default — provided as a
    deployment secret, same as the deploy script.

.PARAMETER MongoSecurityGroupId
    Default: sg-0429199286ae27ecc (Mesh's Mongo security group — the ingress rule granted to
    fraud-detection's task security group is revoked from here before that security group is
    deleted).

.PARAMETER MongoDatabaseName
    Default: fraud_detection_demo.

.PARAMETER CognitoUserPoolId
    Default: us-east-2_D0FCCAyEB.

.EXAMPLE
    ./teardown-fraud-detection-aws.ps1 -MeshBaseUrl "https://mesh.example.com" -MongoConnectionString $env:MESH_MONGO_CONNECTION_STRING
#>

[CmdletBinding()]
param(
    [string]$Region = "us-east-2",
    [string]$ClusterName = "fraud-detection-dev-useast2",

    [Parameter(Mandatory = $true, HelpMessage = "REQUIRED. Base URL of the AWS-deployed Mesh instance this demo's HITL policy entries live in.")]
    [string]$MeshBaseUrl,

    [Parameter(Mandatory = $true, HelpMessage = "REQUIRED. Connection string for the shared Mongo instance. No default on purpose — provided as a deployment secret.")]
    [string]$MongoConnectionString,

    [string]$MongoSecurityGroupId = "sg-0429199286ae27ecc",
    [string]$MongoDatabaseName = "fraud_detection_demo",
    [string]$CognitoUserPoolId = "us-east-2_D0FCCAyEB"
)

$ErrorActionPreference = "Stop"

$BackendServiceName = "fraud-detection-backend"
$FrontendServiceName = "fraud-detection-frontend"
$AlbName = "fraud-detection-dev-useast2"
$TaskSecurityGroupName = "fraud-detection-task-dev-useast2"
$AlbSecurityGroupName = "fraud-detection-alb-dev-useast2"
$CognitoAppClientName = "fraud-detection-demo"
$CognitoSecretName = "fraud-detection/dev/cognito-client-secret"

$script:SecretValues = @($MongoConnectionString)

function Invoke-Aws {
    param([string[]]$Arguments, [string]$ErrorContext, [string[]]$AdditionalSecrets = @())
    $allSecrets = $script:SecretValues + $AdditionalSecrets
    $displayLine = "`$ aws $($Arguments -join ' ')"
    foreach ($secret in $allSecrets) { if ($secret) { $displayLine = $displayLine.Replace($secret, "***REDACTED***") } }
    Write-Host $displayLine -ForegroundColor Gray
    $output = & aws @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        $redacted = ($output | Out-String)
        foreach ($secret in $allSecrets) { if ($secret) { $redacted = $redacted.Replace($secret, "***REDACTED***") } }
        Write-Host $redacted -ForegroundColor Red
        throw "Failed: $ErrorContext (exit code $LASTEXITCODE)"
    }
    return $output
}

Write-Host "=== Verifying AWS login ===" -ForegroundColor Cyan
$callerIdentity = aws sts get-caller-identity 2>$null | ConvertFrom-Json
if (-not $callerIdentity) { throw "Not logged into AWS. Run 'aws login' (or your account's SSO equivalent) first." }
Write-Host "Account: $($callerIdentity.Account), region: $Region" -ForegroundColor Green

# --- Maintenance tasks (HITL scrub, database drop) run FIRST, via ecs run-task inside the
# still-live cluster/task-definition/networking — before any of it gets deleted below. Mesh's
# Mongo is only reachable via a private Cloud Map DNS name inside the VPC; running these from
# the teardown script's own process (e.g. a GitHub Actions hosted runner) cannot reach it at all.
# See deploy-fraud-detection-to-aws.ps1's identical Invoke-EcsMaintenanceTask for the full
# rationale. ---
$clusterExists = $false
aws ecs describe-clusters --region $Region --clusters $ClusterName --query "clusters[?status=='ACTIVE']" 2>$null | Out-Null
if ($LASTEXITCODE -eq 0) { $clusterExists = $true }

if ($clusterExists) {
    $vpc = (& aws ec2 describe-vpcs --region $Region --filters "Name=is-default,Values=true" 2>$null | ConvertFrom-Json).Vpcs[0]
    $VpcId = $vpc.VpcId
    $SubnetIds = (& aws ec2 describe-subnets --region $Region --filters "Name=vpc-id,Values=$VpcId" "Name=default-for-az,Values=true" 2>$null | ConvertFrom-Json).Subnets | ForEach-Object { $_.SubnetId }
    $taskSgForMaintenance = (& aws ec2 describe-security-groups --region $Region --filters "Name=group-name,Values=$TaskSecurityGroupName" 2>$null | ConvertFrom-Json).SecurityGroups

    if ($taskSgForMaintenance -and $taskSgForMaintenance.Count -gt 0 -and $SubnetIds) {
        $TaskSecurityGroupId = $taskSgForMaintenance[0].GroupId

        function Invoke-EcsMaintenanceTask {
            param([string]$Description, [string[]]$Command, [string[]]$AdditionalSecrets = @())
            Write-Host "`n=== $Description ===" -ForegroundColor Cyan
            $overrides = @{ containerOverrides = @(@{ name = $BackendServiceName; command = $Command }) } | ConvertTo-Json -Depth 10
            $tmpOverrides = New-TemporaryFile
            Set-Content -Path $tmpOverrides -Value $overrides -NoNewline
            $networkConfig = "awsvpcConfiguration={subnets=[$($SubnetIds -join ',')],securityGroups=[$TaskSecurityGroupId],assignPublicIp=ENABLED}"
            try {
                $runResult = Invoke-Aws -AdditionalSecrets $AdditionalSecrets -Arguments @(
                    "ecs","run-task","--region",$Region,"--cluster",$ClusterName,"--task-definition",$BackendServiceName,
                    "--launch-type","FARGATE","--network-configuration",$networkConfig,"--overrides","file://$tmpOverrides"
                ) -ErrorContext "ecs run-task ($Description)" | ConvertFrom-Json
            } finally {
                Remove-Item $tmpOverrides -ErrorAction SilentlyContinue
            }
            $taskArn = $runResult.tasks[0].taskArn
            if (-not $taskArn) {
                Write-Host "WARNING: $Description — ecs run-task did not return a task ARN, skipping." -ForegroundColor Yellow
                return
            }
            aws ecs wait tasks-stopped --region $Region --cluster $ClusterName --tasks $taskArn
            $exitCode = (& aws ecs describe-tasks --region $Region --cluster $ClusterName --tasks $taskArn 2>&1 | ConvertFrom-Json).tasks[0].containers[0].exitCode
            if ($exitCode -ne 0) {
                Write-Host "WARNING: $Description failed (container exit code $exitCode) — continuing teardown anyway. Check CloudWatch log group /ecs/$BackendServiceName (task ARN: $taskArn)." -ForegroundColor Yellow
            } else {
                Write-Host "$Description completed successfully." -ForegroundColor Green
            }
        }

        Invoke-EcsMaintenanceTask -Description "Clearing this demo's workflow manifests + HITL policy entries" -Command @(
            "python3","scripts/reset_hitl_policy.py","--mesh-base-url",$MeshBaseUrl,"--mesh-mongo-uri",$MongoConnectionString
        ) -AdditionalSecrets @($MongoConnectionString)

        Invoke-EcsMaintenanceTask -Description "Dropping the $MongoDatabaseName database" -Command @(
            "python3","scripts/drop_database.py","--mongo-uri",$MongoConnectionString,"--db-name",$MongoDatabaseName
        ) -AdditionalSecrets @($MongoConnectionString)
    } else {
        Write-Host "WARNING: task security group or default subnets not found — skipping HITL policy scrub and database drop. Run them manually once VPC access is available." -ForegroundColor Yellow
    }
} else {
    Write-Host "Cluster '$ClusterName' does not exist — nothing to run maintenance tasks against; skipping HITL policy scrub and database drop." -ForegroundColor Yellow
}

Write-Host "`n=== Scaling down + deleting ECS services ===" -ForegroundColor Cyan
foreach ($svc in @($BackendServiceName, $FrontendServiceName)) {
    $existing = (& aws ecs describe-services --region $Region --cluster $ClusterName --services $svc 2>$null | ConvertFrom-Json).services | Where-Object { $_.status -eq "ACTIVE" }
    if ($existing) {
        Write-Host "Draining and deleting service '$svc'..." -ForegroundColor Gray
        aws ecs update-service --region $Region --cluster $ClusterName --service $svc --desired-count 0 2>&1 | Out-Null
        aws ecs delete-service --region $Region --cluster $ClusterName --service $svc --force 2>&1 | Out-Null
    } else {
        Write-Host "Service '$svc' does not exist — skipping." -ForegroundColor Gray
    }
}

Write-Host "`n=== Deleting ALB + target groups ===" -ForegroundColor Cyan
$existingAlb = (& aws elbv2 describe-load-balancers --region $Region --names $AlbName 2>$null | ConvertFrom-Json)
if ($existingAlb -and $existingAlb.LoadBalancers.Count -gt 0) {
    $albArn = $existingAlb.LoadBalancers[0].LoadBalancerArn
    aws elbv2 delete-load-balancer --region $Region --load-balancer-arn $albArn 2>&1 | Out-Null
    Write-Host "Deleted ALB '$AlbName'." -ForegroundColor Gray
} else {
    Write-Host "ALB '$AlbName' does not exist — skipping." -ForegroundColor Gray
}
foreach ($tgName in @("fraud-detection-backend", "fraud-detection-frontend")) {
    $existingTg = (& aws elbv2 describe-target-groups --region $Region --names $tgName 2>$null | ConvertFrom-Json)
    if ($existingTg -and $existingTg.TargetGroups.Count -gt 0) {
        aws elbv2 delete-target-group --region $Region --target-group-arn $existingTg.TargetGroups[0].TargetGroupArn 2>&1 | Out-Null
    }
}

Write-Host "`n=== Deleting ECS cluster ===" -ForegroundColor Cyan
aws ecs describe-clusters --region $Region --clusters $ClusterName --query "clusters[?status=='ACTIVE']" 2>$null | Out-Null
if ($LASTEXITCODE -eq 0) {
    aws ecs delete-cluster --region $Region --cluster $ClusterName 2>&1 | Out-Null
    Write-Host "Deleted cluster '$ClusterName'." -ForegroundColor Gray
} else {
    Write-Host "Cluster '$ClusterName' does not exist — skipping." -ForegroundColor Gray
}

Write-Host "`n=== Deleting ECR repositories ===" -ForegroundColor Cyan
foreach ($repoName in @("fraud-detection-backend", "fraud-detection-frontend")) {
    aws ecr describe-repositories --region $Region --repository-names $repoName 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) {
        aws ecr delete-repository --region $Region --repository-name $repoName --force 2>&1 | Out-Null
        Write-Host "Deleted repository '$repoName' (and every image in it)." -ForegroundColor Gray
    } else {
        Write-Host "Repository '$repoName' does not exist — skipping." -ForegroundColor Gray
    }
}

# ALB/ECS ENIs can take a short while to fully detach after the resources above are deleted —
# security-group deletion fails with DependencyViolation until they do. A few short retries
# covers the normal case without an indefinite wait.
function Remove-SecurityGroupWithRetry {
    param([string]$GroupId, [string]$Label)
    if (-not $GroupId) { return }
    for ($attempt = 1; $attempt -le 6; $attempt++) {
        $result = & aws ec2 delete-security-group --region $Region --group-id $GroupId 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Deleted security group '$Label' ($GroupId)." -ForegroundColor Gray
            return
        }
        if (($result -join "`n") -match "DependencyViolation" -and $attempt -lt 6) {
            Write-Host "Security group '$Label' still has dependent ENIs — retrying in 10s ($attempt/6)..." -ForegroundColor Yellow
            Start-Sleep -Seconds 10
            continue
        }
        Write-Host "WARNING: could not delete security group '$Label' ($GroupId): $result" -ForegroundColor Yellow
        return
    }
}

Write-Host "`n=== Revoking fraud-detection's ingress on Mesh's Mongo security group ===" -ForegroundColor Cyan
$taskSg = (& aws ec2 describe-security-groups --region $Region --filters "Name=group-name,Values=$TaskSecurityGroupName" 2>$null | ConvertFrom-Json).SecurityGroups
if ($taskSg -and $taskSg.Count -gt 0) {
    $taskSgId = $taskSg[0].GroupId
    $revokeResult = & aws ec2 revoke-security-group-ingress --region $Region --group-id $MongoSecurityGroupId --protocol tcp --port 27017 --source-group $taskSgId 2>&1
    if ($LASTEXITCODE -ne 0 -and ($revokeResult -join "`n") -notmatch "InvalidPermission\.NotFound") {
        Write-Host "WARNING: failed to revoke Mongo ingress rule: $revokeResult" -ForegroundColor Yellow
    } else {
        Write-Host "Revoked fraud-detection's access to Mesh's Mongo." -ForegroundColor Gray
    }
} else {
    $taskSgId = $null
    Write-Host "Task security group not found — nothing to revoke." -ForegroundColor Gray
}

Write-Host "`n=== Deleting fraud-detection security groups ===" -ForegroundColor Cyan
Remove-SecurityGroupWithRetry -GroupId $taskSgId -Label $TaskSecurityGroupName
$albSg = (& aws ec2 describe-security-groups --region $Region --filters "Name=group-name,Values=$AlbSecurityGroupName" 2>$null | ConvertFrom-Json).SecurityGroups
if ($albSg -and $albSg.Count -gt 0) {
    Remove-SecurityGroupWithRetry -GroupId $albSg[0].GroupId -Label $AlbSecurityGroupName
}

Write-Host "`n=== Deleting Cognito app client ===" -ForegroundColor Cyan
$existingClients = (& aws cognito-idp list-user-pool-clients --region $Region --user-pool-id $CognitoUserPoolId 2>$null | ConvertFrom-Json).UserPoolClients
$existingClient = $existingClients | Where-Object { $_.ClientName -eq $CognitoAppClientName }
if ($existingClient) {
    aws cognito-idp delete-user-pool-client --region $Region --user-pool-id $CognitoUserPoolId --client-id $existingClient.ClientId 2>&1 | Out-Null
    Write-Host "Deleted Cognito app client '$CognitoAppClientName'." -ForegroundColor Gray
} else {
    Write-Host "Cognito app client '$CognitoAppClientName' does not exist — skipping." -ForegroundColor Gray
}

Write-Host "`n=== Deleting Secrets Manager secret ===" -ForegroundColor Cyan
aws secretsmanager describe-secret --region $Region --secret-id $CognitoSecretName 2>$null | Out-Null
if ($LASTEXITCODE -eq 0) {
    aws secretsmanager delete-secret --region $Region --secret-id $CognitoSecretName --force-delete-without-recovery 2>&1 | Out-Null
    Write-Host "Deleted secret '$CognitoSecretName'." -ForegroundColor Gray
} else {
    Write-Host "Secret '$CognitoSecretName' does not exist — skipping." -ForegroundColor Gray
}

Write-Host "`n✅ Fraud-detection demo torn down on AWS — ECS/ALB/security groups/Cognito client/secret removed, HITL policy entries scrubbed, database dropped." -ForegroundColor Green
