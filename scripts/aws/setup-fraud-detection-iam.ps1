#Requires -Version 5.1
<#
.SYNOPSIS
    ONE-TIME setup: creates the IAM role GitHub Actions assumes (via OIDC) to deploy/tear down
    the fraud-detection demo on AWS. Run once by a human with IAM admin rights — never part of
    the deploy/teardown scripts themselves, matching Mesh's own separation
    (scripts/iam/README.md#github-actions-ci-oidc-setup for the precedent this mirrors).

.DESCRIPTION
    Reuses the GitHub OIDC provider that ALREADY EXISTS in this account for Mesh's own CI
    (arn:aws:iam::<account>:oidc-provider/token.actions.githubusercontent.com) — no new OIDC
    federation setup, just a new role trusting it, scoped to THIS repo's OIDC subject. Mesh's
    own role's trust policy is scoped to repo:searavi/Mesh:environment:dev and cannot be reused
    across repos, so this repo needs its own role.

    Permissions are scoped exactly like Mesh's own MeshRuntimeDeployer policy: every resource
    ARN prefixed fraud-detection-*, PassRole restricted to the ECS tasks service principal only,
    nothing subscription/account-wide.

.PARAMETER GitHubOrg
    Default: searavi (matches this repo's actual GitHub org).

.PARAMETER GitHubRepo
    Default: unified-fraud-detection (the real repo name — distinct from this local worktree's
    directory name).

.PARAMETER GitHubEnvironment
    GitHub Environment name this role's trust policy is scoped to. Default: dev.

.PARAMETER RoleName
    Default: role-fraud-detection-github-actions-dev.

.EXAMPLE
    ./setup-fraud-detection-iam.ps1
#>

[CmdletBinding()]
param(
    [string]$GitHubOrg = "searavi",
    [string]$GitHubRepo = "unified-fraud-detection",
    [string]$GitHubEnvironment = "dev",
    [string]$RoleName = "role-fraud-detection-github-actions-dev",
    [string]$PolicyName = "FraudDetectionDeployer"
)

$ErrorActionPreference = "Stop"

$account = aws sts get-caller-identity | ConvertFrom-Json
if (-not $account) { throw "Not logged into AWS. Run 'aws login' (or your account's SSO equivalent) first." }
$accountId = $account.Account
Write-Host "Account: $accountId" -ForegroundColor Green

$oidcProviderArn = "arn:aws:iam::${accountId}:oidc-provider/token.actions.githubusercontent.com"
aws iam get-open-id-connect-provider --open-id-connect-provider-arn $oidcProviderArn 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "GitHub OIDC provider not found at $oidcProviderArn. This account was expected to already have one (Mesh's own CI uses it) — investigate before creating a second one."
}
Write-Host "Reusing existing GitHub OIDC provider: $oidcProviderArn" -ForegroundColor Green

$trustPolicy = @{
    Version = "2012-10-17"
    Statement = @(
        @{
            Effect = "Allow"
            Principal = @{ Federated = $oidcProviderArn }
            Action = "sts:AssumeRoleWithWebIdentity"
            Condition = @{
                StringEquals = @{
                    "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
                    "token.actions.githubusercontent.com:sub" = "repo:${GitHubOrg}/${GitHubRepo}:environment:${GitHubEnvironment}"
                }
            }
        }
    )
} | ConvertTo-Json -Depth 10

$permissionsPolicy = @{
    Version = "2012-10-17"
    Statement = @(
        @{ Sid = "StsIdentity"; Effect = "Allow"; Action = "sts:GetCallerIdentity"; Resource = "*" }
        @{
            Sid = "SecretsManagerFraudDetection"
            Effect = "Allow"
            Action = @("secretsmanager:DescribeSecret","secretsmanager:CreateSecret","secretsmanager:PutSecretValue","secretsmanager:GetSecretValue","secretsmanager:DeleteSecret","secretsmanager:TagResource")
            Resource = @("arn:aws:secretsmanager:*:${accountId}:secret:fraud-detection/*")
        }
        @{ Sid = "EcrAuth"; Effect = "Allow"; Action = "ecr:GetAuthorizationToken"; Resource = "*" }
        @{
            Sid = "EcrFraudDetectionRepo"
            Effect = "Allow"
            Action = @("ecr:DescribeRepositories","ecr:CreateRepository","ecr:DeleteRepository","ecr:BatchCheckLayerAvailability","ecr:GetDownloadUrlForLayer","ecr:BatchGetImage","ecr:PutImage","ecr:InitiateLayerUpload","ecr:UploadLayerPart","ecr:CompleteLayerUpload")
            Resource = "arn:aws:ecr:*:${accountId}:repository/fraud-detection-*"
        }
        @{
            Sid = "IamFraudDetectionRoles"
            Effect = "Allow"
            Action = @("iam:GetRole","iam:CreateRole","iam:DeleteRole","iam:PutRolePolicy","iam:DeleteRolePolicy","iam:DetachRolePolicy","iam:TagRole")
            Resource = "arn:aws:iam::${accountId}:role/role-fraud-detection-*"
        }
        @{
            Sid = "IamAttachOnlyTaskExecutionPolicy"
            Effect = "Allow"
            Action = "iam:AttachRolePolicy"
            Resource = "arn:aws:iam::${accountId}:role/role-fraud-detection-*"
            Condition = @{ StringEquals = @{ "iam:PolicyARN" = @("arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy") } }
        }
        @{
            Sid = "IamPassRoleToComputeOnly"
            Effect = "Allow"
            Action = "iam:PassRole"
            Resource = "arn:aws:iam::${accountId}:role/role-fraud-detection-*"
            Condition = @{ StringEquals = @{ "iam:PassedToService" = "ecs-tasks.amazonaws.com" } }
        }
        @{
            Sid = "EcsFraudDetection"
            Effect = "Allow"
            Action = @("ecs:CreateCluster","ecs:DeleteCluster","ecs:DescribeClusters","ecs:RegisterTaskDefinition","ecs:DeregisterTaskDefinition","ecs:DescribeTaskDefinition","ecs:CreateService","ecs:UpdateService","ecs:DeleteService","ecs:DescribeServices","ecs:ListTasks","ecs:DescribeTasks","ecs:TagResource")
            Resource = "*"
        }
        @{
            Sid = "Ec2NetworkingReadAndSecurityGroups"
            Effect = "Allow"
            Action = @("ec2:DescribeVpcs","ec2:DescribeSubnets","ec2:DescribeSecurityGroups","ec2:DescribeInstances","ec2:CreateSecurityGroup","ec2:DeleteSecurityGroup","ec2:AuthorizeSecurityGroupIngress","ec2:RevokeSecurityGroupIngress","ec2:CreateTags")
            Resource = "*"
        }
        @{
            Sid = "ElbFraudDetection"
            Effect = "Allow"
            Action = @("elasticloadbalancing:CreateLoadBalancer","elasticloadbalancing:DeleteLoadBalancer","elasticloadbalancing:DescribeLoadBalancers","elasticloadbalancing:CreateTargetGroup","elasticloadbalancing:DeleteTargetGroup","elasticloadbalancing:DescribeTargetGroups","elasticloadbalancing:CreateListener","elasticloadbalancing:DeleteListener","elasticloadbalancing:DescribeListeners","elasticloadbalancing:AddTags")
            Resource = "*"
        }
        @{
            Sid = "LogsFraudDetection"
            Effect = "Allow"
            Action = @("logs:CreateLogGroup","logs:DeleteLogGroup","logs:DescribeLogGroups","logs:PutRetentionPolicy")
            Resource = "arn:aws:logs:*:${accountId}:log-group:/ecs/fraud-detection-*"
        }
        @{
            Sid = "CognitoFraudDetectionAppClient"
            Effect = "Allow"
            Action = @("cognito-idp:CreateUserPoolClient","cognito-idp:DeleteUserPoolClient","cognito-idp:DescribeUserPoolClient","cognito-idp:UpdateUserPoolClient","cognito-idp:DescribeUserPool")
            Resource = "*"
        }
    )
} | ConvertTo-Json -Depth 10

$tmpTrust = New-TemporaryFile
$tmpPerms = New-TemporaryFile
Set-Content -Path $tmpTrust -Value $trustPolicy -NoNewline
Set-Content -Path $tmpPerms -Value $permissionsPolicy -NoNewline

try {
    aws iam get-role --role-name $RoleName 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Role '$RoleName' already exists — updating its trust policy and permissions." -ForegroundColor Yellow
        aws iam update-assume-role-policy --role-name $RoleName --policy-document "file://$tmpTrust"
        if ($LASTEXITCODE -ne 0) { throw "Failed to update trust policy" }
    } else {
        Write-Host "Creating role '$RoleName'..." -ForegroundColor Cyan
        aws iam create-role --role-name $RoleName --assume-role-policy-document "file://$tmpTrust" --description "GitHub Actions OIDC role for deploying the fraud-detection demo (repo: $GitHubOrg/$GitHubRepo, environment: $GitHubEnvironment)"
        if ($LASTEXITCODE -ne 0) { throw "Failed to create role" }
    }

    aws iam put-role-policy --role-name $RoleName --policy-name $PolicyName --policy-document "file://$tmpPerms"
    if ($LASTEXITCODE -ne 0) { throw "Failed to attach permissions policy" }
} finally {
    Remove-Item $tmpTrust, $tmpPerms -ErrorAction SilentlyContinue
}

$roleArn = "arn:aws:iam::${accountId}:role/${RoleName}"
Write-Host "`n✅ Role ready: $roleArn" -ForegroundColor Green
Write-Host "Next: set this as the 'AWS_ROLE_ARN' variable on the '$GitHubEnvironment' GitHub Environment" -ForegroundColor Cyan
Write-Host "for $GitHubOrg/$GitHubRepo (Settings → Environments → $GitHubEnvironment → Environment variables)." -ForegroundColor Cyan
