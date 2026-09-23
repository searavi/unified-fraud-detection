#Requires -Version 5.1
<#
.SYNOPSIS
    Deploy the fraud-detection demo's backend + frontend to AWS ECS Fargate, sharing Mesh's
    existing EC2 Mongo instance and Cognito user pool.

.DESCRIPTION
    Creates a dedicated ECS cluster (fraud-detection-*, separate from Mesh's own cluster —
    zero cost difference under Fargate, cleaner isolation), builds+pushes both images to ECR,
    grants the task security group ingress to Mesh's Mongo EC2 instance's security group,
    registers this demo's own callback URL on Mesh's EXISTING admin Cognito app client rather
    than creating a separate client (Mesh's deployed Auth:IdPAudience trusts exactly one Cognito
    audience — a client fraud-detection created itself would never pass Mesh's audience check;
    see deploy script's own Cognito section and Get-MeshAdminToken's comment for the full
    root-cause chain), runs both services behind one ALB (plain HTTP — no ACM/Route53 domain
    configured; same fallback Mesh's own AWS deploy uses without -CustomDomain), seeds the
    shared Mongo database, and resets this demo's HITL policy entries to blocking (tag-scoped —
    see reset_hitl_policy.py; this Mesh deployment may be shared with other demos).

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

    # Must match setup-fraud-detection-iam.ps1's defaults — that script provisions this account
    # and its password once; this script only ever authenticates as it.
    [string]$AutomationUsername = "fraud-detection-automation@synchtron-test.local",
    [string]$AutomationSecretName = "fraud-detection/dev/automation-user-password",

    # Mesh's OWN pre-existing Cognito admin app client (mesh-runtime-admins user pool) —
    # confirmed live to be the one and only audience Mesh's deployed Auth:IdPAudience trusts.
    # The HITL-scrub service account authenticates against THIS client, not this demo's own
    # $cognitoClientId, or Mesh rejects the resulting token with 401 on audience mismatch.
    [string]$MeshAdminClientId = "2fvmn3og01l444d57fbojla6k6",

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
$AlbSecurityGroupId = Get-OrCreateSecurityGroup -Name $AlbSecurityGroupName -Description "Fraud-detection demo ALB - inbound HTTP from internet"
$TaskSecurityGroupId = Get-OrCreateSecurityGroup -Name $TaskSecurityGroupName -Description "Fraud-detection demo ECS tasks - inbound from ALB only"

# Idempotent: AuthorizeSecurityGroupIngress errors (InvalidPermission.Duplicate) if the rule
# already exists — treated as success, everything else re-thrown.
function Grant-IngressIfMissing {
    param([string]$GroupId, [string]$Protocol, [int]$Port, [string]$SourceGroupId)
    $result = & aws ec2 authorize-security-group-ingress --region $Region --group-id $GroupId --protocol $Protocol --port $Port --source-group $SourceGroupId 2>&1
    if ($LASTEXITCODE -ne 0 -and ($result -join "`n") -notmatch "InvalidPermission\.Duplicate") {
        throw "Failed to authorize ingress on $GroupId from $SourceGroupId : $result"
    }
}

foreach ($albPort in 80, 8081) {
    $albIngressResult = & aws ec2 authorize-security-group-ingress --region $Region --group-id $AlbSecurityGroupId --protocol tcp --port $albPort --cidr "0.0.0.0/0" 2>&1
    if ($LASTEXITCODE -ne 0 -and ($albIngressResult -join "`n") -notmatch "InvalidPermission\.Duplicate") {
        throw "Failed to authorize public HTTP ingress on port ${albPort} for ALB security group: $albIngressResult"
    }
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

# AmazonECSTaskExecutionRolePolicy covers ECR pull + logs:CreateLogStream/PutLogEvents, but NOT
# logs:CreateLogGroup (needed because the task defs below set awslogs-create-group=true) or
# secretsmanager:GetSecretValue on this demo's own secrets (any task def field referencing a
# fraud-detection/* secret ARN needs this at container start to resolve it). Idempotent — always
# (re-)put, not just on first creation, so a role created before this policy existed still gets it.
$executionRoleExtraPolicy = @{
    Version   = "2012-10-17"
    Statement = @(
        @{
            Sid      = "CreateOwnLogGroups"
            Effect   = "Allow"
            Action   = "logs:CreateLogGroup"
            Resource = "arn:aws:logs:${Region}:${AccountId}:log-group:/ecs/fraud-detection-*"
        }
        @{
            Sid      = "ReadOwnSecrets"
            Effect   = "Allow"
            Action   = "secretsmanager:GetSecretValue"
            Resource = "arn:aws:secretsmanager:${Region}:${AccountId}:secret:fraud-detection/*"
        }
    )
} | ConvertTo-Json -Depth 10
$tmpExecPolicy = New-TemporaryFile
Set-Content -Path $tmpExecPolicy -Value $executionRoleExtraPolicy -NoNewline
try {
    Invoke-Aws -Arguments @("iam","put-role-policy","--role-name",$ExecutionRoleName,"--policy-name","fraud-detection-execution-extras","--policy-document","file://$tmpExecPolicy") -ErrorContext "put-role-policy (execution role extras)" | Out-Null
} finally {
    Remove-Item $tmpExecPolicy -ErrorAction SilentlyContinue
}

# Image build moved to AFTER CloudFront/URL setup below (see that section for why: `next build`
# bakes BACKEND_URL/NEXT_PUBLIC_BACKEND_URL in as build args, so the final URL must be known
# before the frontend image builds — a real ordering dependency the multi-stage Dockerfile fix
# introduced, not present in the old single-stage image where build and start shared one live
# container environment).
$ecrHost = "$AccountId.dkr.ecr.$Region.amazonaws.com"

Write-Host "`n=== Ensuring ECS cluster ===" -ForegroundColor Cyan
# describe-clusters exits 0 even when --clusters names a cluster that doesn't exist (it just
# returns an empty "clusters" array, no error) — existence must be checked from the array
# content, not $LASTEXITCODE.
$activeClusters = (aws ecs describe-clusters --region $Region --clusters $ClusterName --query "clusters[?status=='ACTIVE']" --output json 2>$null | ConvertFrom-Json)
if (-not $activeClusters -or $activeClusters.Count -eq 0) {
    Invoke-Aws -Arguments @("ecs","create-cluster","--region",$Region,"--cluster-name",$ClusterName) -ErrorContext "create-cluster" | Out-Null
}

Write-Host "`n=== Ensuring Application Load Balancer ===" -ForegroundColor Cyan
$existingAlb = (& aws elbv2 describe-load-balancers --region $Region --names $AlbName 2>$null | ConvertFrom-Json)
if ($existingAlb -and $existingAlb.LoadBalancers.Count -gt 0) {
    $alb = $existingAlb.LoadBalancers[0]
} else {
    $albArgs = @("elbv2","create-load-balancer","--region",$Region,"--name",$AlbName,"--type","application","--scheme","internet-facing","--subnets") + $SubnetIds + @("--security-groups",$AlbSecurityGroupId)
    $alb = (Invoke-Aws -Arguments $albArgs -ErrorContext "create-load-balancer" | ConvertFrom-Json).LoadBalancers[0]
}
$AlbArn = $alb.LoadBalancerArn
$AlbDnsName = $alb.DNSName
Write-Host "ALB: $AlbDnsName" -ForegroundColor Green

function Get-OrCreateTargetGroup {
    param([string]$Name, [int]$Port, [string]$HealthCheckPath)
    $existing = (& aws elbv2 describe-target-groups --region $Region --names $Name 2>$null | ConvertFrom-Json)
    if ($existing -and $existing.TargetGroups.Count -gt 0) {
        $tg = $existing.TargetGroups[0]
        if ($tg.HealthCheckPath -ne $HealthCheckPath) {
            Write-Host "Target group '$Name' health check path drifted ('$($tg.HealthCheckPath)') — correcting to '$HealthCheckPath'." -ForegroundColor Yellow
            Invoke-Aws -Arguments @("elbv2","modify-target-group","--region",$Region,"--target-group-arn",$tg.TargetGroupArn,"--health-check-path",$HealthCheckPath) -ErrorContext "modify-target-group ($Name)" | Out-Null
        }
        return $tg.TargetGroupArn
    }
    $created = Invoke-Aws -Arguments @(
        "elbv2","create-target-group","--region",$Region,"--name",$Name,"--protocol","HTTP","--port",$Port,
        "--vpc-id",$VpcId,"--target-type","ip","--health-check-path",$HealthCheckPath
    ) -ErrorContext "create-target-group ($Name)" | ConvertFrom-Json
    return $created.TargetGroups[0].TargetGroupArn
}

$BackendTargetGroupArn = Get-OrCreateTargetGroup -Name "fraud-detection-backend" -Port 4000 -HealthCheckPath "/health"
# "/" 307-redirects to "/flagged" (app/page.tsx) — the target group's default Matcher only
# accepts 200, so a health check against "/" fails forever and ECS churns tasks continuously,
# each briefly serving real traffic before being killed. Confirmed live: container logs showed a
# perfectly healthy Next.js startup while the target group reported every task unhealthy on
# exactly this. Check the redirect's actual destination instead.
$FrontendTargetGroupArn = Get-OrCreateTargetGroup -Name "fraud-detection-frontend" -Port 8080 -HealthCheckPath "/flagged"

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

# --- CloudFront: the ALB is deliberately plain HTTP (no ACM/Route53 domain — see script header),
# but Cognito's OAuth callback URL must be HTTPS (its only non-HTTPS exemption is
# http://localhost, which doesn't apply to a real deployed URL). CloudFront's default
# *.cloudfront.net domain gets a valid AWS-managed cert for free — no custom domain, no ACM DNS
# validation. TLS terminates at CloudFront; it talks to the ALB over plain HTTP behind it
# (OriginProtocolPolicy http-only). One distribution, two origins (same ALB, different ports —
# matching the ALB's own two-listener split): the default behavior forwards to the frontend
# (:80), and explicit path patterns for every backend-owned route forward to the backend
# (:8081). Both behaviors disable caching entirely (Managed-CachingDisabled) — none of this
# app's responses are static/cacheable, and a stale cache would be a confusing demo bug for
# zero benefit at this traffic level — and use Managed-AllViewer so cookies, the OAuth
# code/state query string, and SSE headers (Accept: text/event-stream) all reach the origin
# unmodified.
#
# KNOWN LIMIT: CloudFront's custom-origin read timeout tops out at 60s without an AWS support
# quota increase (default 30s; requesting up to 60s needs no ticket, beyond 60s does) — set to
# the max here. investigation_service.py's stream_investigation blocks on Mesh's
# POST {workflowId}/execute until the workflow finishes; if a real investigation run ever takes
# longer than 60s end-to-end, CloudFront will return 504 before the backend responds. Fine for
# this demo's workflow today — flagging so it isn't a silent surprise if the workflow grows.
Write-Host "`n=== Ensuring CloudFront distribution (HTTPS for the Cognito OAuth callback) ===" -ForegroundColor Cyan
$CloudFrontComment = $AlbName
$existingDistributions = (& aws cloudfront list-distributions --region $Region 2>$null | ConvertFrom-Json).DistributionList.Items
$existingDistribution = $existingDistributions | Where-Object { $_.Comment -eq $CloudFrontComment }
if ($existingDistribution) {
    $CloudFrontDomain = $existingDistribution.DomainName
    Write-Host "Reusing existing CloudFront distribution: $CloudFrontDomain" -ForegroundColor Yellow

    # ALB DNS names are NOT stable across delete+recreate, even with the same -AlbName tag —
    # teardown-fraud-detection-aws.ps1 has no CloudFront-deletion step (a known gap), so a
    # teardown+redeploy cycle reuses THIS distribution but gets a brand-new ALB underneath it.
    # Without this, the distribution's Origins keep pointing at the deleted ALB's old DNS name
    # forever, and every request 502s with "CloudFront wasn't able to resolve the origin domain
    # name" — confirmed live. GetDistributionConfig/UpdateDistribution require resending the
    # FULL config (same full-replace API shape as UpdateUserPool/UpdateUserPoolClient elsewhere
    # in this script set) — fetch it, patch only the two origins' DomainName, put back everything
    # else unchanged, using the ETag GetDistributionConfig returns as the required --if-match.
    $distConfigResponse = Invoke-Aws -Arguments @("cloudfront","get-distribution-config","--id",$existingDistribution.Id) -ErrorContext "get-distribution-config ($($existingDistribution.Id))" | ConvertFrom-Json
    $currentConfig = $distConfigResponse.DistributionConfig
    $etag = $distConfigResponse.ETag
    $staleOrigins = $currentConfig.Origins.Items | Where-Object { $_.DomainName -ne $AlbDnsName }
    if ($staleOrigins) {
        Write-Host "Distribution's origins point at a stale ALB DNS name — updating to '$AlbDnsName'..." -ForegroundColor Yellow
        foreach ($origin in $currentConfig.Origins.Items) { $origin.DomainName = $AlbDnsName }
        $updateConfigJson = $currentConfig | ConvertTo-Json -Depth 20
        $tmpUpdateConfig = New-TemporaryFile
        Set-Content -Path $tmpUpdateConfig -Value $updateConfigJson -NoNewline
        try {
            Invoke-Aws -Arguments @("cloudfront","update-distribution","--id",$existingDistribution.Id,"--distribution-config","file://$tmpUpdateConfig","--if-match",$etag) -ErrorContext "update-distribution ($($existingDistribution.Id))" | Out-Null
        } finally {
            Remove-Item $tmpUpdateConfig -ErrorAction SilentlyContinue
        }
        Write-Host "Origins updated. Allow a few minutes for the change to propagate to all edge locations." -ForegroundColor Yellow
    } else {
        Write-Host "Distribution's origins already point at the current ALB — no update needed." -ForegroundColor Green
    }
} else {
    $cachingDisabledPolicyId = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"   # AWS Managed-CachingDisabled
    $allViewerOriginRequestPolicyId = "216adef6-5c7f-47e4-b989-5492eafa07d3"   # AWS Managed-AllViewer
    $backendPathPatterns = @("/auth/*", "/health", "/users/*", "/flagged-accounts", "/flagged-accounts/*", "/accounts/*", "/investigation/*")

    function New-CacheBehavior {
        param([string]$PathPattern, [string]$TargetOriginId)
        @{
            PathPattern          = $PathPattern
            TargetOriginId       = $TargetOriginId
            ViewerProtocolPolicy = "redirect-to-https"
            CachePolicyId        = $cachingDisabledPolicyId
            OriginRequestPolicyId = $allViewerOriginRequestPolicyId
            AllowedMethods       = @{
                Quantity = 7
                Items    = @("GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE")
                CachedMethods = @{ Quantity = 2; Items = @("GET", "HEAD") }
            }
            Compress             = $true
        }
    }

    $distributionConfig = @{
        CallerReference = "$AlbName-$(Get-Random)"
        Comment         = $CloudFrontComment
        Enabled         = $true
        Origins         = @{
            Quantity = 2
            Items    = @(
                @{
                    Id                = "frontend-origin"
                    DomainName        = $AlbDnsName
                    CustomOriginConfig = @{
                        HTTPPort             = 80
                        HTTPSPort            = 443
                        OriginProtocolPolicy = "http-only"
                        OriginSslProtocols   = @{ Quantity = 1; Items = @("TLSv1.2") }
                        OriginReadTimeout    = 30
                        OriginKeepaliveTimeout = 5
                    }
                }
                @{
                    Id                = "backend-origin"
                    DomainName        = $AlbDnsName
                    CustomOriginConfig = @{
                        HTTPPort             = 8081
                        HTTPSPort            = 443
                        OriginProtocolPolicy = "http-only"
                        OriginSslProtocols   = @{ Quantity = 1; Items = @("TLSv1.2") }
                        OriginReadTimeout    = 60
                        OriginKeepaliveTimeout = 5
                    }
                }
            )
        }
        DefaultCacheBehavior = (New-CacheBehavior -PathPattern $null -TargetOriginId "frontend-origin")
        CacheBehaviors  = @{
            Quantity = $backendPathPatterns.Count
            Items    = @($backendPathPatterns | ForEach-Object { New-CacheBehavior -PathPattern $_ -TargetOriginId "backend-origin" })
        }
        PriceClass      = "PriceClass_100"
    }
    # DefaultCacheBehavior has no PathPattern field — strip the $null one New-CacheBehavior set.
    $distributionConfig.DefaultCacheBehavior.Remove("PathPattern")

    $distributionJson = $distributionConfig | ConvertTo-Json -Depth 20
    $tmpDistConfig = New-TemporaryFile
    Set-Content -Path $tmpDistConfig -Value $distributionJson -NoNewline
    try {
        $created = Invoke-Aws -Arguments @("cloudfront","create-distribution","--distribution-config","file://$tmpDistConfig") -ErrorContext "create-distribution" | ConvertFrom-Json
    } finally {
        Remove-Item $tmpDistConfig -ErrorAction SilentlyContinue
    }
    $CloudFrontDomain = $created.Distribution.DomainName
    Write-Host "Created CloudFront distribution: $CloudFrontDomain" -ForegroundColor Green
    Write-Host "NOTE: new distributions take ~15-20 minutes to fully deploy — expect errors hitting it until then." -ForegroundColor Yellow
}

$backendUrl = "https://$CloudFrontDomain"
$frontendUrl = "https://$CloudFrontDomain"

if (-not $SkipBuild) {
    Write-Host "`n=== Building + pushing images to ECR ===" -ForegroundColor Cyan
    $loginPassword = Invoke-Aws -Arguments @("ecr","get-login-password","--region",$Region) -ErrorContext "ecr get-login-password"
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

        # --build-arg: see frontend.Dockerfile's build-stage comment — `next build` bakes these
        # into a static routes manifest + the client bundle; a runtime-only env var can't override
        # them anymore once the image is built.
        docker build -f frontend.Dockerfile `
            --build-arg "BACKEND_URL=$backendUrl" `
            --build-arg "NEXT_PUBLIC_BACKEND_URL=$backendUrl" `
            -t "${ecrHost}/${FrontendRepoName}:${ImageTag}" .
        if ($LASTEXITCODE -ne 0) { throw "docker build (frontend) failed" }
        docker push "${ecrHost}/${FrontendRepoName}:${ImageTag}"
        if ($LASTEXITCODE -ne 0) { throw "docker push (frontend) failed" }
    } finally {
        Pop-Location
    }
} else {
    Write-Host "`n=== Skipping image builds — reusing ${ImageTag} already in ECR ===" -ForegroundColor Yellow
}

$CognitoDomain = (Invoke-Aws -Arguments @("cognito-idp","describe-user-pool","--region",$Region,"--user-pool-id",$CognitoUserPoolId,"--query","UserPool.Domain","--output","text") -ErrorContext "describe-user-pool (domain)").Trim()

Write-Host "`n=== Registering this demo's callback with Mesh's admin app client ===" -ForegroundColor Cyan
$redirectUri = "$backendUrl/auth/callback"
# Deliberately NOT creating fraud-detection's own Cognito app client — confirmed live: Mesh's
# deployed Auth:IdPAudience trusts exactly one Cognito audience (this demo's own client would
# never pass Mesh's audience check; see Get-MeshAdminToken's comment for the full root-cause
# chain). Registering this callback against $MeshAdminClientId instead means real end-user
# login goes through the SAME client Mesh already trusts, no Mesh-side change needed. That
# client is public (no secret) — nothing for this demo to store in Secrets Manager either.
# update-user-pool-client REPLACES the whole client config, not just CallbackURLs — must fetch
# and resubmit the client's full current settings, only adding this URL if it's not already
# present, so this never clobbers whatever else already uses that client (including your own
# interactive admin login).
$meshClientDetail = (Invoke-Aws -Arguments @("cognito-idp","describe-user-pool-client","--region",$Region,"--user-pool-id",$CognitoUserPoolId,"--client-id",$MeshAdminClientId) -ErrorContext "describe-user-pool-client (Mesh admin client)" | ConvertFrom-Json).UserPoolClient
$existingCallbackUrls = @($meshClientDetail.CallbackURLs)
if ($existingCallbackUrls -notcontains $redirectUri) {
    $updatedCallbackUrls = $existingCallbackUrls + @($redirectUri)
    $updateClientArgs = @(
        "cognito-idp","update-user-pool-client","--region",$Region,"--user-pool-id",$CognitoUserPoolId,
        "--client-id",$MeshAdminClientId
    )
    $updateClientArgs += @("--callback-urls") + $updatedCallbackUrls
    $updateClientArgs += @("--supported-identity-providers") + @($meshClientDetail.SupportedIdentityProviders)
    $updateClientArgs += @("--allowed-o-auth-flows") + @($meshClientDetail.AllowedOAuthFlows)
    $updateClientArgs += @("--allowed-o-auth-scopes") + @($meshClientDetail.AllowedOAuthScopes)
    $updateClientArgs += @("--explicit-auth-flows") + @($meshClientDetail.ExplicitAuthFlows)
    $updateClientArgs += @("--allowed-o-auth-flows-user-pool-client")
    Invoke-Aws -Arguments $updateClientArgs -ErrorContext "update-user-pool-client (add fraud-detection callback)" | Out-Null
    Write-Host "Added $redirectUri to Mesh admin client's callback URLs." -ForegroundColor Green
} else {
    Write-Host "$redirectUri already registered on Mesh admin client." -ForegroundColor Yellow
}
$cognitoClientId = $MeshAdminClientId
Write-Host "Using Mesh's admin app client for login: $cognitoClientId (redirect URI: $redirectUri)" -ForegroundColor Green

# Mints a real Mesh admin-role token for the HITL-scrub maintenance step — /local/token is
# Production-disabled, and HitlPoliciesController requires [Authorize(Policy = "AdminPolicy")]
# on every route. Authenticates as the dedicated service account setup-fraud-detection-iam.ps1
# provisions (USER_PASSWORD_AUTH against a real Cognito user in the "mesh-admins" group —
# client_credentials can't work here, it's a client-identity token with no user, so it never
# carries cognito:groups). Returns the ID token specifically: Mesh's admin-claim fallback reads
# cognito:groups, which Cognito only puts on the ID token by default, not the access token —
# same reasoning as auth_service.py's own Cognito path.
#
# Deliberately authenticates against $MeshAdminClientId (Mesh's OWN pre-existing admin app
# client), NOT this demo's own $cognitoClientId — confirmed live: Mesh's deployed
# Auth:IdPAudience trusts exactly one Cognito audience, and a token issued to a different app
# client is rejected 401 before AdminPolicy is even evaluated (JWT bearer audience check fails
# first). That client is public (no secret, confirmed via describe-user-pool-client) and already
# has ALLOW_USER_PASSWORD_AUTH enabled — using the plain (non-admin) InitiateAuth flow here means
# zero configuration changes to that shared, Mesh-owned client, and no SECRET_HASH to compute.
function Get-MeshAdminToken {
    $password = (aws secretsmanager get-secret-value --region $Region --secret-id $AutomationSecretName --query "SecretString" --output text 2>&1)
    if ($LASTEXITCODE -ne 0) { throw "Failed to fetch '$AutomationUsername' password from Secrets Manager ($AutomationSecretName) — has setup-fraud-detection-iam.ps1 been run?" }
    $script:SecretValues += $password

    $authParams = "USERNAME=$AutomationUsername,PASSWORD=$password"
    $authResult = Invoke-Aws -Arguments @(
        "cognito-idp","initiate-auth","--region",$Region,
        "--client-id",$MeshAdminClientId,"--auth-flow","USER_PASSWORD_AUTH",
        "--auth-parameters",$authParams
    ) -ErrorContext "initiate-auth ($AutomationUsername)" -AdditionalSecrets @($password) | ConvertFrom-Json
    $idToken = $authResult.AuthenticationResult.IdToken
    if (-not $idToken) { throw "initiate-auth succeeded but returned no IdToken for '$AutomationUsername'" }
    $script:SecretValues += $idToken
    return $idToken
}


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
    OPA_BUNDLE_MAX_DELAY_SECONDS = "60"
} -Secrets @()

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

$meshAdminToken = Get-MeshAdminToken
Invoke-EcsMaintenanceTask -Description "Clearing this demo's prior workflow manifests + HITL policy entries" -Command @(
    "python3","scripts/reset_hitl_policy.py","--mesh-base-url",$MeshBaseUrl,"--mesh-mongo-uri",$MongoConnectionString,"--mesh-admin-token",$meshAdminToken
) -AdditionalSecrets @($MongoConnectionString, $meshAdminToken)

Write-Host "`n✅ Fraud-detection demo deployed to AWS." -ForegroundColor Green
Write-Host "   App (frontend + backend, unified behind CloudFront): $frontendUrl" -ForegroundColor Cyan
Write-Host "   OAuth callback registered with Cognito: $redirectUri" -ForegroundColor Cyan
Write-Host "   Direct ALB access (debugging only, plain HTTP, bypasses CloudFront):" -ForegroundColor Gray
Write-Host "     Frontend: http://$AlbDnsName" -ForegroundColor Gray
Write-Host "     Backend:  http://${AlbDnsName}:8081" -ForegroundColor Gray
Write-Host "   Real-user login requires IAM Identity Center SAML federation into the 'mesh-admins'" -ForegroundColor Yellow
Write-Host "   group (same as Mesh's own admin path)." -ForegroundColor Yellow
if (-not $existingDistribution) {
    Write-Host "   NOTE: CloudFront distribution was just created — allow ~15-20 minutes before the app URL works." -ForegroundColor Yellow
}
