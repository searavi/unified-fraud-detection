#Requires -Version 5.1
<#
.SYNOPSIS
    ONE-TIME setup: creates the IAM role GitHub Actions assumes (via OIDC) to deploy/tear down
    the fraud-detection demo on AWS, AND the dedicated KMS key fraud-detection agents sign their
    RFC 7523 assertions with. Run once by a human with IAM admin rights — never part of the
    deploy/teardown scripts themselves, matching Mesh's own separation
    (scripts/iam/README.md#github-actions-ci-oidc-setup for the precedent this mirrors).

    The KMS key is deliberately separate from Mesh's own shared OAuth-signing key
    (Auth:SigningKeyReference on the Mesh deployment) — fraud-detection's agents get their own
    key rather than reusing Mesh's, so the two are never coupled. Two grants are required for
    agents to actually authenticate with it: the key's own resource policy must let the AWS
    agent task role (role-synktron-agent-task-dev-useast2) Sign/GetPublicKey/DescribeKey, and
    Mesh's own task role (role-synchtron-mesh-task-dev-useast2) needs GetPublicKey (verify-only,
    never Sign) added to its existing 'kms-sign' inline policy — Mesh verifies agent assertion
    signatures under its own AWS identity, a separate principal from the agent's signing
    identity. Run against Mesh's own IAM role is intentionally NOT scoped by this script's own
    generated FraudDetectionDeployer policy (that policy is for GitHub Actions' role, a
    different principal than whoever runs this script by hand).

    ALSO creates the dedicated Cognito service account (a native user, not IIC/SAML) the
    deploy/teardown scripts authenticate as to call Mesh's HITL policy API
    (/api/v1/hitl/policies/{tenantId} requires [Authorize(Policy = "AdminPolicy")] on every
    route -- /local/token is Production-disabled, so a real admin-role token is the only way
    in). A Cognito client_credentials grant CANNOT satisfy this: it's a client-identity token
    with no user, so it never carries cognito:groups. ADMIN_USER_PASSWORD_AUTH against a real
    user who is a member of the real "mesh-admins" Cognito group -- the exact mechanism already
    proven for interactive human logins -- is the only non-interactive path that actually
    produces a token Mesh's AdminRoleAuthorizationHandler accepts. Deliberately a NEW dedicated
    user, not the existing mesh-test-admin@synchtron-test.local -- reusing an unowned shared
    credential risks breaking whatever else already depends on it, and blurs ownership of this
    demo's own service identity. Creating a Cognito user/adding it to a group needs
    AdminCreateUser/AdminSetUserPassword/AdminAddUserToGroup, a real step up from the app-
    CLIENT-only permissions the GitHub Actions role has -- exactly the kind of privileged,
    rarely-needed action this one-time script exists to keep out of the routinely-CI-executed
    deploy script. The deploy/teardown scripts only ever CONSUME what this script provisions
    (AdminInitiateAuth as the already-existing user) -- they never create or modify the account
    itself.

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

.PARAMETER CognitoUserPoolId
    Default: us-east-2_D0FCCAyEB (Mesh's existing "mesh-runtime-admins" user pool).

.PARAMETER AutomationUsername
    Native Cognito user created (or reused if it already exists) as the HITL-scrub service
    account. Default: fraud-detection-automation@synchtron-test.local.

.PARAMETER AutomationSecretName
    Secrets Manager secret the generated password is stored in. Default:
    fraud-detection/dev/automation-user-password.

.EXAMPLE
    ./setup-fraud-detection-iam.ps1
#>

[CmdletBinding()]
param(
    [string]$GitHubOrg = "searavi",
    [string]$GitHubRepo = "unified-fraud-detection",
    [string]$GitHubEnvironment = "dev",
    [string]$RoleName = "role-fraud-detection-github-actions-dev",
    [string]$PolicyName = "FraudDetectionDeployer",

    [string]$Region = "us-east-2",
    [string]$KmsAliasName = "alias/fraud-detection-agent-signing-dev",
    [string]$AgentTaskRoleName = "role-synktron-agent-task-dev-useast2",
    [string]$MeshTaskRoleName = "role-synchtron-mesh-task-dev-useast2",

    [string]$CognitoUserPoolId = "us-east-2_D0FCCAyEB",
    [string]$AutomationUsername = "fraud-detection-automation@synchtron-test.local",
    [string]$AutomationSecretName = "fraud-detection/dev/automation-user-password"
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
        @{
            Sid = "CognitoFraudDetectionAdminAuth"
            Effect = "Allow"
            # InitiateAuth is what deploy/teardown actually call (Mesh's own pre-existing admin
            # app client is public and only has ALLOW_USER_PASSWORD_AUTH, not the ADMIN_ variant
            # -- see deploy-fraud-detection-to-aws.ps1's Get-MeshAdminToken). AdminInitiateAuth
            # is granted too since it's uncertain whether InitiateAuth is IAM-authorized at all
            # for this account (some Cognito user-facing APIs aren't) -- harmless either way if
            # unused.
            Action = @("cognito-idp:InitiateAuth", "cognito-idp:AdminInitiateAuth")
            Resource = "arn:aws:cognito-idp:${Region}:${accountId}:userpool/${CognitoUserPoolId}"
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

Write-Host "`n=== Fraud-detection agent signing key ===" -ForegroundColor Cyan
$existingKeyId = (aws kms describe-key --key-id $KmsAliasName --region $Region --query "KeyMetadata.KeyId" --output text 2>$null)
if ($LASTEXITCODE -eq 0 -and $existingKeyId) {
    Write-Host "KMS key already exists under alias '$KmsAliasName' — reusing it." -ForegroundColor Yellow
    $keyId = $existingKeyId.Trim()
} else {
    Write-Host "Creating dedicated KMS signing key..." -ForegroundColor Cyan
    $keyJson = aws kms create-key `
        --description "Fraud-detection agent JWT assertion signing key ($GitHubEnvironment)" `
        --key-usage SIGN_VERIFY `
        --key-spec RSA_2048 `
        --region $Region `
        --tags "TagKey=Project,TagValue=fraud-detection" "TagKey=Environment,TagValue=$GitHubEnvironment" `
        --output json | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or -not $keyJson) { throw "Failed to create KMS signing key" }
    $keyId = $keyJson.KeyMetadata.KeyId

    aws kms create-alias --alias-name $KmsAliasName --target-key-id $keyId --region $Region
    if ($LASTEXITCODE -ne 0) { throw "Failed to create KMS alias '$KmsAliasName'" }
}
$keyArn = "arn:aws:kms:${Region}:${accountId}:key/${keyId}"
Write-Host "Signing key: $keyArn" -ForegroundColor Green

# Key's own resource policy: let the AWS agent task role sign with it and read its public key.
# Root always keeps kms:* (the default AWS gives every CMK) so this account's own IAM policies
# stay the actual authorization boundary for every other principal — this statement is additive.
$keyPolicy = @{
    Version   = "2012-10-17"
    Statement = @(
        @{
            Sid       = "EnableIamUserPermissions"
            Effect    = "Allow"
            Principal = @{ AWS = "arn:aws:iam::${accountId}:root" }
            Action    = "kms:*"
            Resource  = "*"
        }
        @{
            Sid       = "AllowAgentTaskRoleSignAndVerify"
            Effect    = "Allow"
            Principal = @{ AWS = "arn:aws:iam::${accountId}:role/${AgentTaskRoleName}" }
            Action    = @("kms:Sign", "kms:GetPublicKey", "kms:DescribeKey")
            Resource  = "*"
        }
    )
} | ConvertTo-Json -Depth 10
$tmpKeyPolicy = New-TemporaryFile
Set-Content -Path $tmpKeyPolicy -Value $keyPolicy -NoNewline
try {
    aws kms put-key-policy --key-id $keyId --policy-name default --policy "file://$tmpKeyPolicy" --region $Region
    if ($LASTEXITCODE -ne 0) { throw "Failed to attach key policy granting '$AgentTaskRoleName' sign/verify" }
} finally {
    Remove-Item $tmpKeyPolicy -ErrorAction SilentlyContinue
}
Write-Host "Granted '$AgentTaskRoleName' Sign/GetPublicKey/DescribeKey on the key." -ForegroundColor Green

# Mesh's own task role verifies agent assertion signatures under its own AWS identity (a
# separate principal from the agent's) — it needs GetPublicKey only, never Sign, and this must
# be MERGED into its existing 'kms-sign' inline policy, not overwritten: that policy already
# grants Sign+GetPublicKey on Mesh's own shared OAuth-signing key, which this script must not
# touch or remove.
$existingMeshPolicyJson = (aws iam get-role-policy --role-name $MeshTaskRoleName --policy-name kms-sign --query "PolicyDocument" --output json 2>$null)
$meshFraudSid = "VerifyFraudDetectionAgentAssertions"
if ($LASTEXITCODE -eq 0 -and $existingMeshPolicyJson) {
    $meshPolicyObj = $existingMeshPolicyJson | ConvertFrom-Json
    $statements = @($meshPolicyObj.Statement | Where-Object { $_.Sid -ne $meshFraudSid })
} else {
    Write-Host "'$MeshTaskRoleName' has no existing 'kms-sign' policy — creating one from scratch." -ForegroundColor Yellow
    $statements = @()
}
$statements += @{
    Sid      = $meshFraudSid
    Effect   = "Allow"
    Action   = "kms:GetPublicKey"
    Resource = $keyArn
}
$meshPolicy = @{ Version = "2012-10-17"; Statement = $statements } | ConvertTo-Json -Depth 10
$tmpMeshPolicy = New-TemporaryFile
Set-Content -Path $tmpMeshPolicy -Value $meshPolicy -NoNewline
try {
    aws iam put-role-policy --role-name $MeshTaskRoleName --policy-name kms-sign --policy-document "file://$tmpMeshPolicy"
    if ($LASTEXITCODE -ne 0) { throw "Failed to grant '$MeshTaskRoleName' GetPublicKey on the fraud-detection signing key" }
} finally {
    Remove-Item $tmpMeshPolicy -ErrorAction SilentlyContinue
}
Write-Host "Granted '$MeshTaskRoleName' GetPublicKey (verify-only) on the key." -ForegroundColor Green

Write-Host "`nNext: pass this as -AgentKeyVaultSigningKeyUri to register-fraud-agents-aws.ps1:" -ForegroundColor Cyan
Write-Host "  $keyArn" -ForegroundColor Green

Write-Host "`n=== HITL automation service account ===" -ForegroundColor Cyan
aws cognito-idp admin-get-user --region $Region --user-pool-id $CognitoUserPoolId --username $AutomationUsername 2>$null | Out-Null
$automationUserExists = ($LASTEXITCODE -eq 0)
if ($automationUserExists) {
    Write-Host "Service account '$AutomationUsername' already exists — leaving its password as-is." -ForegroundColor Yellow
} else {
    Write-Host "Creating service account '$AutomationUsername'..." -ForegroundColor Cyan
    aws cognito-idp admin-create-user --region $Region --user-pool-id $CognitoUserPoolId `
        --username $AutomationUsername --message-action SUPPRESS `
        --user-attributes "Name=email,Value=$AutomationUsername" "Name=email_verified,Value=true"
    if ($LASTEXITCODE -ne 0) { throw "Failed to create Cognito user '$AutomationUsername'" }

    # Randomly generated, satisfies Cognito's default password policy (length + all four
    # character classes) — never logged or displayed, only handed to Secrets Manager below.
    $randomBytes = New-Object byte[] 24
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($randomBytes)
    $automationPassword = "Aa1!" + ([Convert]::ToBase64String($randomBytes) -replace '[+/=]', '')

    aws cognito-idp admin-set-user-password --region $Region --user-pool-id $CognitoUserPoolId `
        --username $AutomationUsername --password $automationPassword --permanent | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to set password for '$AutomationUsername'" }

    aws secretsmanager describe-secret --region $Region --secret-id $AutomationSecretName 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) {
        aws secretsmanager put-secret-value --region $Region --secret-id $AutomationSecretName --secret-string $automationPassword | Out-Null
    } else {
        aws secretsmanager create-secret --region $Region --name $AutomationSecretName --secret-string $automationPassword | Out-Null
    }
    if ($LASTEXITCODE -ne 0) { throw "Failed to store '$AutomationUsername' password in Secrets Manager" }
    Write-Host "Password stored in Secrets Manager: $AutomationSecretName" -ForegroundColor Green
}

# Idempotent regardless of branch above — AWS accepts re-adding an existing member without error,
# so this also self-heals a user that exists but somehow isn't in the group yet.
aws cognito-idp admin-add-user-to-group --region $Region --user-pool-id $CognitoUserPoolId `
    --username $AutomationUsername --group-name "mesh-admins"
if ($LASTEXITCODE -ne 0) { throw "Failed to add '$AutomationUsername' to the 'mesh-admins' group" }
Write-Host "'$AutomationUsername' is a member of 'mesh-admins'." -ForegroundColor Green

Write-Host "`nDeploy/teardown scripts authenticate this account against Mesh's OWN pre-existing" -ForegroundColor Cyan
Write-Host "admin app client (the only Cognito audience Mesh's deployed Auth:IdPAudience trusts)" -ForegroundColor Cyan
Write-Host "— no changes needed to this demo's own app client for that to work." -ForegroundColor Cyan
