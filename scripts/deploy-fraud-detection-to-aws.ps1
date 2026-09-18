#Requires -Version 5.1
<#
.SYNOPSIS
    Deploy the fraud-detection demo's backend + frontend to AWS ECS Fargate, sharing Mesh's
    existing EC2 Mongo instance and Cognito user pool.

.DESCRIPTION
    Creates a dedicated ECS cluster (fraud-detection-*, separate from Mesh's own cluster —
    zero cost difference under Fargate, cleaner isolation), builds+pushes both images to ECR,
    grants the task security group ingress to Mesh's Mongo EC2 instance's security group,
    creates a NEW Cognito App Client in Mesh's EXISTING user pool (not reusing Mesh's own
    client), runs both services behind one ALB (plain HTTP — no ACM/Route53 domain configured;
    same fallback Mesh's own AWS deploy uses without -CustomDomain), seeds the shared Mongo
    database, and resets this demo's HITL policy entries to blocking (tag-scoped — see
    reset_hitl_policy.py; this Mesh deployment may be shared with other demos).

    Assumes the caller is already authenticated (`aws sts get-caller-identity` succeeds) with
    the permissions granted by scripts/aws/setup-fraud-detection-iam.ps1 (run that once first,
    by a human with IAM admin rights) — this script never touches IAM roles/trust policies
    itself beyond the two ECS runtime roles it creates for its own tasks.

.PARAMETER Region
    Default: us-east-2 (same region Mesh's own AWS deployment uses).

.PARAMETER ClusterName
    Default: fraud-detection-dev-useast2.

.PARAMETER ImageTag
    Default: latest.

.PARAMETER MeshBaseUrl
    REQUIRED. Base URL of the AWS-deployed Mesh instance this demo talks to.

.PARAMETER MongoConnectionString
    REQUIRED. Connection string for the shared Mongo instance — Mesh's own EC2 Mongo, reachable
    from within the same VPC via its Cloud Map private DNS name
    (mongodb.mesh-internal-dev-useast2.local, confirmed live) or its private IP. No default on
    purpose: provided as a deployment secret (GitHub Actions secret), matching
    deploy-fraud-detection-to-azure.ps1's identical treatment of this same parameter — a
    connection string can carry embedded credentials and must never silently default.

.PARAMETER MongoSecurityGroupId
    Security group on Mesh's Mongo EC2 instance to add an ingress rule to. Default:
    sg-0429199286ae27ecc (confirmed live: security group "synchtron-mesh-mongo-dev-useast2") —
    a resource identifier, not a secret, so a default is fine here (matches how the Azure script
    defaults -ResourceGroupName/-AcrName).

.PARAMETER MongoDatabaseName
    Default: fraud_detection_demo.

.PARAMETER CognitoUserPoolId
    Default: us-east-2_D0FCCAyEB (Mesh's existing "mesh-runtime-admins" user pool — reused, not
    recreated; this script creates a NEW app client inside it, never touches Mesh's own client).

.PARAMETER SkipBuild
    Skip the docker build/push steps and reuse whatever image already carries -ImageTag in ECR.

.EXAMPLE
    ./deploy-fraud-detection-to-aws.ps1 -MeshBaseUrl "https://mesh.example.com" -MongoConnectionString $env:MESH_MONGO_CONNECTION_STRING
#>

[CmdletBinding()]
param(
    [string]$Region = "us-east-2",
    [string]$ClusterName = "fraud-detection-dev-useast2",
    [string]$ImageTag = "latest",

    [Parameter(Mandatory = $true, HelpMessage = "REQUIRED. Base URL of the AWS-deployed Mesh instance this demo talks to.")]
    [string]$MeshBaseUrl,

    [Parameter(Mandatory = $true, HelpMessage = "REQUIRED. Connection string for the shared Mongo instance (same one Mesh's operational store uses). No default on purpose — provided as a deployment secret.")]
    [string]$MongoConnectionString,

    [string]$MongoSecurityGroupId = "sg-0429199286ae27ecc",
    [string]$MongoDatabaseName = "fraud_detection_demo",
    [string]$CognitoUserPoolId = "us-east-2_D0FCCAyEB",

    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$BackendRepoName = "fraud-detection-backend"
$FrontendRepoName = "fraud-detection-frontend"
$BackendServiceName = "fraud-detection-backend"
$FrontendServiceName = "fraud-detection-frontend"
$ExecutionRoleName = "role-fraud-detection-execution-dev-useast2"
$TaskRoleName = "role-fraud-detection-task-dev-useast2"
$TaskSecurityGroupName = "fraud-detection-task-dev-useast2"
$AlbSecurityGroupName = "fraud-detection-alb-dev-useast2"
$AlbName = "fraud-detection-dev-useast2"
$CognitoAppClientName = "fraud-detection-demo"

$script:SecretValues = @($MongoConnectionString)

function Invoke-Aws {
    param([string[]]$Arguments, [string]$ErrorContext, [string[]]$AdditionalSecrets = @())
    $allSecrets = $script:SecretValues + $AdditionalSecrets
    $displayLine = "`$ aws $($Arguments -join ' ')"
    foreach ($secret in $allSecrets) {
        if ($secret) { $displayLine = $displayLine.Replace($secret, "***REDACTED***") }
    }
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
$AccountId = $callerIdentity.Account
Write-Host "Account: $AccountId, region: $Region" -ForegroundColor Green

# --- Networking discovery (same default-VPC approach as deploy-meshruntime-to-aws.ps1) ---
Write-Host "`n=== Discovering default VPC + subnets ===" -ForegroundColor Cyan
$vpc = (Invoke-Aws -Arguments @("ec2","describe-vpcs","--region",$Region,"--filters","Name=is-default,Values=true") -ErrorContext "describe-vpcs" | ConvertFrom-Json).Vpcs[0]
if (-not $vpc) { throw "No default VPC found in $Region." }
$VpcId = $vpc.VpcId
$subnets = (Invoke-Aws -Arguments @("ec2","describe-subnets","--region",$Region,"--filters","Name=vpc-id,Values=$VpcId","Name=default-for-az,Values=true") -ErrorContext "describe-subnets" | ConvertFrom-Json).Subnets
if (-not $subnets -or $subnets.Count -eq 0) { throw "No default subnets found in VPC $VpcId." }
$SubnetIds = $subnets | ForEach-Object { $_.SubnetId }
Write-Host "VPC: $VpcId, subnets: $($SubnetIds -join ', ')" -ForegroundColor Green

function Get-OrCreateSecurityGroup {
    param([string]$Name, [string]$Description)
    $existing = (Invoke-Aws -Arguments @("ec2","describe-security-groups","--region",$Region,"--filters","Name=group-name,Values=$Name","Name=vpc-id,Values=$VpcId") -ErrorContext "describe-security-groups ($Name)" | ConvertFrom-Json).SecurityGroups
    if ($existing -and $existing.Count -gt 0) { return $existing[0].GroupId }
    $created = Invoke-Aws -Arguments @("ec2","create-security-group","--region",$Region,"--group-name",$Name,"--description",$Description,"--vpc-id",$VpcId) -ErrorContext "create-security-group ($Name)" | ConvertFrom-Json
    return $created.GroupId
}

Write-Host "`n=== Ensuring security groups ===" -ForegroundColor Cyan
$AlbSecurityGroupId = Get-OrCreateSecurityGroup -Name $AlbSecurityGroupName -Description "Fraud-detection demo ALB — inbound HTTP from internet"
$TaskSecurityGroupId = Get-OrCreateSecurityGroup -Name $TaskSecurityGroupName -Description "Fraud-detection demo ECS tasks — inbound from ALB only"

# Idempotent: AuthorizeSecurityGroupIngress errors (InvalidPermission.Duplicate) if the rule
# already exists — treated as success, everything else re-thrown.
function Grant-IngressIfMissing {
    param([string]$GroupId, [string]$Protocol, [int]$Port, [string]$SourceGroupId)
    $result = & aws ec2 authorize-security-group-ingress --region $Region --group-id $GroupId --protocol $Protocol --port $Port --source-group $SourceGroupId 2>&1
    if ($LASTEXITCODE -ne 0 -and ($result -join "`n") -notmatch "InvalidPermission\.Duplicate") {
        throw "Failed to authorize ingress on $GroupId from $SourceGroupId : $result"
    }
}

$albIngressResult = & aws ec2 authorize-security-group-ingress --region $Region --group-id $AlbSecurityGroupId --protocol tcp --port 80 --cidr "0.0.0.0/0" 2>&1
if ($LASTEXITCODE -ne 0 -and ($albIngressResult -join "`n") -notmatch "InvalidPermission\.Duplicate") {
    throw "Failed to authorize public HTTP ingress on ALB security group: $albIngressResult"
}
Grant-IngressIfMissing -GroupId $TaskSecurityGroupId -Protocol "tcp" -Port 4000 -SourceGroupId $AlbSecurityGroupId
Grant-IngressIfMissing -GroupId $TaskSecurityGroupId -Protocol "tcp" -Port 8080 -SourceGroupId $AlbSecurityGroupId

Write-Host "`n=== Granting fraud-detection tasks access to Mesh's Mongo (security-group ingress) ===" -ForegroundColor Cyan
Grant-IngressIfMissing -GroupId $MongoSecurityGroupId -Protocol "tcp" -Port 27017 -SourceGroupId $TaskSecurityGroupId
Write-Host "Task security group $TaskSecurityGroupId can now reach Mongo on port 27017." -ForegroundColor Green

# --- IAM runtime roles (ECS task execution + task role) — created here, not in the one-time
# IAM setup script, matching Mesh's own Ensure-EcsIamRoles convention: these are workload roles
# the GH Actions deploy identity is permitted to create (scoped to role-fraud-detection-*), not
# privileged, human-provisioned trust boundaries like the GH Actions role itself. ---
function Get-OrCreateEcsRole {
    param([string]$RoleName, [string]$ManagedPolicyArn)
    aws iam get-role --role-name $RoleName 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) {
        $trust = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ecs-tasks.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
        $tmpTrust = New-TemporaryFile
        Set-Content -Path $tmpTrust -Value $trust -NoNewline
        try {
            Invoke-Aws -Arguments @("iam","create-role","--role-name",$RoleName,"--assume-role-policy-document","file://$tmpTrust") -ErrorContext "create-role ($RoleName)" | Out-Null
        } finally {
            Remove-Item $tmpTrust -ErrorAction SilentlyContinue
        }
        if ($ManagedPolicyArn) {
            Invoke-Aws -Arguments @("iam","attach-role-policy","--role-name",$RoleName,"--policy-arn",$ManagedPolicyArn) -ErrorContext "attach-role-policy ($RoleName)" | Out-Null
        }
        Write-Host "Created role $RoleName" -ForegroundColor Green
        Start-Sleep -Seconds 8  # IAM eventual consistency — ECS will reject a too-fresh role ARN.
    }
    return "arn:aws:iam::${AccountId}:role/${RoleName}"
}

Write-Host "`n=== Ensuring ECS execution/task roles ===" -ForegroundColor Cyan
$ExecutionRoleArn = Get-OrCreateEcsRole -RoleName $ExecutionRoleName -ManagedPolicyArn "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
$TaskRoleArn = Get-OrCreateEcsRole -RoleName $TaskRoleName -ManagedPolicyArn $null

if (-not $SkipBuild) {
    Write-Host "`n=== Building + pushing images to ECR ===" -ForegroundColor Cyan
    $loginPassword = Invoke-Aws -Arguments @("ecr","get-login-password","--region",$Region) -ErrorContext "ecr get-login-password"
    $ecrHost = "$AccountId.dkr.ecr.$Region.amazonaws.com"
    $loginPassword | docker login --username AWS --password-stdin $ecrHost
    if ($LASTEXITCODE -ne 0) { throw "docker login to ECR failed" }

    foreach ($repoName in @($BackendRepoName, $FrontendRepoName)) {
        aws ecr describe-repositories --region $Region --repository-names $repoName 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Invoke-Aws -Arguments @("ecr","create-repository","--region",$Region,"--repository-name",$repoName) -ErrorContext "create-repository ($repoName)" | Out-Null
        }
    }

    Push-Location $RepoRoot
    try {
        docker build -f backend.Dockerfile -t "${ecrHost}/${BackendRepoName}:${ImageTag}" .
        if ($LASTEXITCODE -ne 0) { throw "docker build (backend) failed" }
        docker push "${ecrHost}/${BackendRepoName}:${ImageTag}"
        if ($LASTEXITCODE -ne 0) { throw "docker push (backend) failed" }

        docker build -f frontend.Dockerfile -t "${ecrHost}/${FrontendRepoName}:${ImageTag}" .
        if ($LASTEXITCODE -ne 0) { throw "docker build (frontend) failed" }
        docker push "${ecrHost}/${FrontendRepoName}:${ImageTag}"
        if ($LASTEXITCODE -ne 0) { throw "docker push (frontend) failed" }
    } finally {
        Pop-Location
    }
} else {
    Write-Host "`n=== Skipping image builds — reusing ${ImageTag} already in ECR ===" -ForegroundColor Yellow
    $ecrHost = "$AccountId.dkr.ecr.$Region.amazonaws.com"
}

Write-Host "`n=== Ensuring ECS cluster ===" -ForegroundColor Cyan
aws ecs describe-clusters --region $Region --clusters $ClusterName --query "clusters[?status=='ACTIVE']" 2>$null | Out-Null
$clusterActive = ($LASTEXITCODE -eq 0)
if (-not $clusterActive) {
    Invoke-Aws -Arguments @("ecs","create-cluster","--region",$Region,"--cluster-name",$ClusterName) -ErrorContext "create-cluster" | Out-Null
}

Write-Host "`n=== Ensuring Application Load Balancer ===" -ForegroundColor Cyan
$existingAlb = (& aws elbv2 describe-load-balancers --region $Region --names $AlbName 2>$null | ConvertFrom-Json)
if ($existingAlb -and $existingAlb.LoadBalancers.Count -gt 0) {
    $alb = $existingAlb.LoadBalancers[0]
} else {
    $alb = (Invoke-Aws -Arguments @("elbv2","create-load-balancer","--region",$Region,"--name",$AlbName,"--type","application","--scheme","internet-facing","--subnets") + $SubnetIds + @("--security-groups",$AlbSecurityGroupId) -ErrorContext "create-load-balancer" | ConvertFrom-Json).LoadBalancers[0]
}
$AlbArn = $alb.LoadBalancerArn
$AlbDnsName = $alb.DNSName
Write-Host "ALB: $AlbDnsName" -ForegroundColor Green

function Get-OrCreateTargetGroup {
    param([string]$Name, [int]$Port, [string]$HealthCheckPath)
    $existing = (& aws elbv2 describe-target-groups --region $Region --names $Name 2>$null | ConvertFrom-Json)
    if ($existing -and $existing.TargetGroups.Count -gt 0) { return $existing.TargetGroups[0].TargetGroupArn }
    $created = Invoke-Aws -Arguments @(
        "elbv2","create-target-group","--region",$Region,"--name",$Name,"--protocol","HTTP","--port",$Port,
        "--vpc-id",$VpcId,"--target-type","ip","--health-check-path",$HealthCheckPath
    ) -ErrorContext "create-target-group ($Name)" | ConvertFrom-Json
    return $created.TargetGroups[0].TargetGroupArn
}

$BackendTargetGroupArn = Get-OrCreateTargetGroup -Name "fraud-detection-backend" -Port 4000 -HealthCheckPath "/health"
$FrontendTargetGroupArn = Get-OrCreateTargetGroup -Name "fraud-detection-frontend" -Port 8080 -HealthCheckPath "/"

# One ALB, two listeners: :80 -> frontend (what the audience visits), :8081 -> backend
# (OAuth callback + direct API access). Avoids the cost/time of a second ALB for a demo.
function Get-OrCreateListener {
    param([int]$Port, [string]$TargetGroupArn)
    $existing = (& aws elbv2 describe-listeners --region $Region --load-balancer-arn $AlbArn 2>$null | ConvertFrom-Json)
    $match = $existing.Listeners | Where-Object { $_.Port -eq $Port }
    if ($match) { return }
    Invoke-Aws -Arguments @(
        "elbv2","create-listener","--region",$Region,"--load-balancer-arn",$AlbArn,"--protocol","HTTP","--port",$Port,
        "--default-actions","Type=forward,TargetGroupArn=$TargetGroupArn"
    ) -ErrorContext "create-listener ($Port)" | Out-Null
}
Get-OrCreateListener -Port 80 -TargetGroupArn $FrontendTargetGroupArn
Get-OrCreateListener -Port 8081 -TargetGroupArn $BackendTargetGroupArn

$backendUrl = "http://${AlbDnsName}:8081"
$frontendUrl = "http://$AlbDnsName"

$CognitoDomain = (Invoke-Aws -Arguments @("cognito-idp","describe-user-pool","--region",$Region,"--user-pool-id",$CognitoUserPoolId,"--query","UserPool.Domain","--output","text") -ErrorContext "describe-user-pool (domain)").Trim()

Write-Host "`n=== Creating Cognito app client for this demo ===" -ForegroundColor Cyan
$redirectUri = "$backendUrl/auth/callback"
$existingClients = (& aws cognito-idp list-user-pool-clients --region $Region --user-pool-id $CognitoUserPoolId 2>$null | ConvertFrom-Json).UserPoolClients
$existingClient = $existingClients | Where-Object { $_.ClientName -eq $CognitoAppClientName }
if ($existingClient) {
    Invoke-Aws -Arguments @(
        "cognito-idp","update-user-pool-client","--region",$Region,"--user-pool-id",$CognitoUserPoolId,
        "--client-id",$existingClient.ClientId,"--callback-urls",$redirectUri,
        "--supported-identity-providers","COGNITO","IIC",
        "--allowed-o-auth-flows","code","--allowed-o-auth-scopes","email","openid","profile",
        "--allowed-o-auth-flows-user-pool-client"
    ) -ErrorContext "update-user-pool-client" | Out-Null
    $cognitoClientId = $existingClient.ClientId
} else {
    $created = Invoke-Aws -Arguments @(
        "cognito-idp","create-user-pool-client","--region",$Region,"--user-pool-id",$CognitoUserPoolId,
        "--client-name",$CognitoAppClientName,"--generate-secret",
        "--callback-urls",$redirectUri,
        "--supported-identity-providers","COGNITO","IIC",
        "--allowed-o-auth-flows","code","--allowed-o-auth-scopes","email","openid","profile",
        "--allowed-o-auth-flows-user-pool-client",
        "--explicit-auth-flows","ALLOW_REFRESH_TOKEN_AUTH"
    ) -ErrorContext "create-user-pool-client" | ConvertFrom-Json
    $cognitoClientId = $created.UserPoolClient.ClientId
}
$cognitoDetail = Invoke-Aws -Arguments @("cognito-idp","describe-user-pool-client","--region",$Region,"--user-pool-id",$CognitoUserPoolId,"--client-id",$cognitoClientId) -ErrorContext "describe-user-pool-client" | ConvertFrom-Json
$cognitoClientSecret = $cognitoDetail.UserPoolClient.ClientSecret
$script:SecretValues += $cognitoClientSecret
Write-Host "Cognito app client ready: $cognitoClientId (redirect URI: $redirectUri)" -ForegroundColor Green

Write-Host "`n=== Storing secrets in Secrets Manager ===" -ForegroundColor Cyan
function Set-SecretValue {
    param([string]$Name, [string]$Value)
    aws secretsmanager describe-secret --region $Region --secret-id $Name 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Invoke-Aws -Arguments @("secretsmanager","put-secret-value","--region",$Region,"--secret-id",$Name,"--secret-string",$Value) -ErrorContext "put-secret-value ($Name)" -AdditionalSecrets @($Value) | Out-Null
    } else {
        Invoke-Aws -Arguments @("secretsmanager","create-secret","--region",$Region,"--name",$Name,"--secret-string",$Value) -ErrorContext "create-secret ($Name)" -AdditionalSecrets @($Value) | Out-Null
    }
}
$cognitoSecretName = "fraud-detection/dev/cognito-client-secret"
Set-SecretValue -Name $cognitoSecretName -Value $cognitoClientSecret
$cognitoSecretArn = (Invoke-Aws -Arguments @("secretsmanager","describe-secret","--region",$Region,"--secret-id",$cognitoSecretName) -ErrorContext "describe-secret" | ConvertFrom-Json).ARN

function Register-TaskDefinition {
    param([string]$Family, [string]$Image, [int]$Port, [hashtable]$EnvVars, [array]$Secrets)
    $envVarList = $EnvVars.GetEnumerator() | ForEach-Object { @{ name = $_.Key; value = $_.Value } }
    $taskDef = @{
        family = $Family
        networkMode = "awsvpc"
        requiresCompatibilities = @("FARGATE")
        cpu = "512"
        memory = "1024"
        executionRoleArn = $ExecutionRoleArn
        taskRoleArn = $TaskRoleArn
        containerDefinitions = @(
            @{
                name = $Family
                image = $Image
                portMappings = @(@{ containerPort = $Port; protocol = "tcp" })
                environment = @($envVarList)
                secrets = $Secrets
                logConfiguration = @{
                    logDriver = "awslogs"
                    options = @{
                        "awslogs-group" = "/ecs/$Family"
                        "awslogs-region" = $Region
                        "awslogs-stream-prefix" = "ecs"
                        "awslogs-create-group" = "true"
                    }
                }
            }
        )
    } | ConvertTo-Json -Depth 10
    $tmpTaskDef = New-TemporaryFile
    Set-Content -Path $tmpTaskDef -Value $taskDef -NoNewline
    try {
        Invoke-Aws -Arguments @("ecs","register-task-definition","--region",$Region,"--cli-input-json","file://$tmpTaskDef") -ErrorContext "register-task-definition ($Family)" | Out-Null
    } finally {
        Remove-Item $tmpTaskDef -ErrorAction SilentlyContinue
    }
}

Write-Host "`n=== Registering task definitions ===" -ForegroundColor Cyan
Register-TaskDefinition -Family $BackendServiceName -Image "${ecrHost}/${BackendRepoName}:${ImageTag}" -Port 4000 -EnvVars @{
    MESH_BASE_URL = $MeshBaseUrl
    MONGODB_CONNECTION_STRING = $MongoConnectionString
    MONGODB_DATABASE = $MongoDatabaseName
    AWS_REGION = $Region
    COGNITO_USER_POOL_ID = $CognitoUserPoolId
    COGNITO_DOMAIN = $CognitoDomain
    COGNITO_CLIENT_ID = $cognitoClientId
    OAUTH_REDIRECT_URI = $redirectUri
    FRONTEND_ORIGIN = $frontendUrl
} -Secrets @(@{ name = "COGNITO_CLIENT_SECRET"; valueFrom = $cognitoSecretArn })

Register-TaskDefinition -Family $FrontendServiceName -Image "${ecrHost}/${FrontendRepoName}:${ImageTag}" -Port 8080 -EnvVars @{
    BACKEND_URL = $backendUrl
    NEXT_PUBLIC_BACKEND_URL = $backendUrl
} -Secrets @()

function Get-OrCreateService {
    param([string]$ServiceName, [string]$TaskFamily, [int]$Port, [string]$TargetGroupArn)
    $existing = (& aws ecs describe-services --region $Region --cluster $ClusterName --services $ServiceName 2>$null | ConvertFrom-Json).services | Where-Object { $_.status -eq "ACTIVE" }
    if ($existing) {
        Invoke-Aws -Arguments @("ecs","update-service","--region",$Region,"--cluster",$ClusterName,"--service",$ServiceName,"--task-definition",$TaskFamily,"--desired-count","1") -ErrorContext "update-service ($ServiceName)" | Out-Null
        return
    }
    Invoke-Aws -Arguments @(
        "ecs","create-service","--region",$Region,"--cluster",$ClusterName,"--service-name",$ServiceName,
        "--task-definition",$TaskFamily,"--desired-count","1","--launch-type","FARGATE",
        "--network-configuration","awsvpcConfiguration={subnets=[$($SubnetIds -join ',')],securityGroups=[$TaskSecurityGroupId],assignPublicIp=ENABLED}",
        "--load-balancers","targetGroupArn=$TargetGroupArn,containerName=$TaskFamily,containerPort=$Port"
    ) -ErrorContext "create-service ($ServiceName)" | Out-Null
}

Write-Host "`n=== Creating/updating ECS services ===" -ForegroundColor Cyan
Get-OrCreateService -ServiceName $BackendServiceName -TaskFamily $BackendServiceName -Port 4000 -TargetGroupArn $BackendTargetGroupArn
Get-OrCreateService -ServiceName $FrontendServiceName -TaskFamily $FrontendServiceName -Port 8080 -TargetGroupArn $FrontendTargetGroupArn

Write-Host "`n=== Waiting for services to stabilize (can take a few minutes) ===" -ForegroundColor Cyan
aws ecs wait services-stable --region $Region --cluster $ClusterName --services $BackendServiceName $FrontendServiceName
if ($LASTEXITCODE -ne 0) { Write-Host "WARNING: services did not stabilize within the wait timeout — check 'aws ecs describe-services' for details." -ForegroundColor Yellow }

# Runs a one-off command inside a Fargate task using the backend's own task definition/image
# and networking (VPC subnets + task security group) — NOT the caller's own process. Mesh's
# Mongo is only reachable via a private Cloud Map DNS name inside that VPC; on a GitHub Actions
# hosted runner (or any machine outside the VPC), a direct python3 call from the deploy script's
# own process cannot resolve it at all. Reuses whichever image/task-def was just registered
# above, so the maintenance scripts always match what's actually deployed.
function Invoke-EcsMaintenanceTask {
    param([string]$Description, [string[]]$Command, [string[]]$AdditionalSecrets = @())
    Write-Host "`n=== $Description ===" -ForegroundColor Cyan

    $overrides = @{
        containerOverrides = @(@{ name = $BackendServiceName; command = $Command })
    } | ConvertTo-Json -Depth 10
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
    if (-not $taskArn) { throw "$Description : ecs run-task did not return a task ARN" }

    aws ecs wait tasks-stopped --region $Region --cluster $ClusterName --tasks $taskArn
    $taskDetail = (& aws ecs describe-tasks --region $Region --cluster $ClusterName --tasks $taskArn 2>&1 | ConvertFrom-Json).tasks[0]
    $exitCode = $taskDetail.containers[0].exitCode
    if ($exitCode -ne 0) {
        Write-Host "$Description failed (container exit code $exitCode). Check CloudWatch log group /ecs/$BackendServiceName for the task's output (task ARN: $taskArn)." -ForegroundColor Red
        throw "$Description failed"
    }
    Write-Host "$Description completed successfully." -ForegroundColor Green
}

Invoke-EcsMaintenanceTask -Description "Seeding the shared Mongo database" -Command @(
    "python3","scripts/seed_mongo.py","--mongo-uri",$MongoConnectionString,"--db-name",$MongoDatabaseName,"--clear"
) -AdditionalSecrets @($MongoConnectionString)

Invoke-EcsMaintenanceTask -Description "Clearing this demo's prior workflow manifests + HITL policy entries" -Command @(
    "python3","scripts/reset_hitl_policy.py","--mesh-base-url",$MeshBaseUrl,"--mesh-mongo-uri",$MongoConnectionString
) -AdditionalSecrets @($MongoConnectionString)

Write-Host "`n✅ Fraud-detection demo deployed to AWS." -ForegroundColor Green
Write-Host "   Backend:  $backendUrl" -ForegroundColor Cyan
Write-Host "   Frontend: $frontendUrl" -ForegroundColor Cyan
Write-Host "   NOTE: /auth/login and /auth/callback are not implemented in the backend yet" -ForegroundColor Yellow
Write-Host "   (Workstream B, Cognito variant) — until then, Mesh calls from this deployment" -ForegroundColor Yellow
Write-Host "   will fail for admin-gated actions." -ForegroundColor Yellow
Write-Host "   Real-user login requires IAM Identity Center SAML federation into the 'mesh-admins'" -ForegroundColor Yellow
Write-Host "   group (same as Mesh's own admin path) — see this session's notes for details." -ForegroundColor Yellow
