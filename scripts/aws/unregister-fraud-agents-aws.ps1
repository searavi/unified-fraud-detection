#Requires -Version 5.1
<#
.SYNOPSIS
    Fully unregisters the 4 fraud-detection agents from the AWS-deployed Mesh instance —
    the Mesh registry row AND the underlying ECS service/secrets it provisioned.

.DESCRIPTION
    CONFIRMED GAP in Mesh itself (AdminController.cs DeleteAgent, ~line 771-799): deleting an
    agent registration only removes the Mesh registry row. It never calls
    IContainerOrchestrator.DeleteAsync — that method is fully implemented (scales the ECS
    service to 0, deletes it, cleans up its Secrets Manager entries) but is wired to fire only
    on deploy-failure rollback, never on manual deletion via the Admin API. Left alone, the
    ECS service keeps running and billing indefinitely after "unregistering" an agent.

    This script does what Mesh's own DeleteAsync would do, directly via AWS CLI, replicating its
    exact naming (confirmed from EcsFargateContainerOrchestrator.cs and its companion
    deploy-agent-container-to-ecs.ps1's Get-SanitizedName, which is documented to stay
    byte-for-byte identical to the C# side):
      - ECS service name: SanitizeName("<DnsNameLabelPrefix>-<agentId>") = "synktron-agent-<id>"
        (lowercased, non-[a-z0-9] runs collapsed to single hyphens).
      - Secrets Manager prefix: "synktron-agents/<Environment>/<SanitizeName(agentId)>/" — NOT
        the service name; this one omits the DnsNameLabelPrefix.
      - Cluster/environment: confirmed live from Mesh's own ECS task definition env vars
        (ContainerRuntime__Aws__ClusterName / ContainerRuntime__Aws__Environment) — defaults
        below match what was confirmed, override if this deployment's config ever changes.

    Never touches the shared cluster, subnets, security group, or IAM roles — those are
    infrastructure this orchestrator (and this script) never owns the lifecycle of, matching
    EcsFargateContainerOrchestrator.DeleteAsync's own explicit scope.

.PARAMETER MeshBaseUrl
    REQUIRED. Base URL of the AWS-deployed Mesh instance.

.PARAMETER MeshAdminToken
    REQUIRED. A real admin-role Mesh bearer token.

.PARAMETER Region
    Default: us-east-2.

.PARAMETER ClusterName
    Default: synchtron-mesh-dev-useast2 (confirmed live — agents deploy into Mesh's own cluster,
    not a separate one).

.PARAMETER Environment
    Default: dev (confirmed live — ContainerRuntime__Aws__Environment on Mesh's own task def).

.PARAMETER DnsNameLabelPrefix
    Default: synktron-agent (EcsFargateContainerOrchestrator's default; only override if this
    deployment was configured with a non-default ContainerRuntimeOptions.DnsNameLabelPrefix).

.PARAMETER AgentEcrRepoName
    ECR repository the agent image was pushed to (see register-fraud-agents-aws.ps1). Only
    needed with -DeleteEcrImages.

.PARAMETER DeleteEcrImages
    Also delete the ECR repository (and every image in it) once all 4 agents are torn down.
    Off by default — the same repo/image may still be in use by a differently-tagged deploy.

.EXAMPLE
    ./unregister-fraud-agents-aws.ps1 -MeshBaseUrl "https://mesh.example.com" -MeshAdminToken $env:MESH_ADMIN_TOKEN -DeleteEcrImages -AgentEcrRepoName "agents/fraud-agent"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "REQUIRED. Base URL of the AWS-deployed Mesh instance.")]
    [string]$MeshBaseUrl,

    [Parameter(Mandatory = $true, HelpMessage = "REQUIRED. A real admin-role Mesh bearer token.")]
    [string]$MeshAdminToken,

    [string]$Region = "us-east-2",
    [string]$ClusterName = "synchtron-mesh-dev-useast2",
    [string]$Environment = "dev",
    [string]$DnsNameLabelPrefix = "synktron-agent",
    [string]$AgentEcrRepoName = "",
    [switch]$DeleteEcrImages
)

$ErrorActionPreference = "Stop"

$AgentIds = @("alert_validation", "data_collection", "llm_agent", "report_generation")

function Get-SanitizedName {
    # Must stay byte-for-byte identical to EcsFargateContainerOrchestrator.SanitizeName (C# side)
    # and deploy-agent-container-to-ecs.ps1's own Get-SanitizedName — see this script's
    # .DESCRIPTION for why.
    param([string]$Name)
    $normalized = ($Name.ToLowerInvariant() -replace '[^a-z0-9]+', '-').Trim('-')
    if ($normalized.Length -eq 0) { return $normalized }
    return $normalized.Substring(0, [Math]::Min($normalized.Length, 63)).TrimEnd('-')
}

$headers = @{ Authorization = "Bearer $MeshAdminToken" }

foreach ($agentId in $AgentIds) {
    Write-Host "`n=== Unregistering agent '$agentId' ===" -ForegroundColor Cyan

    try {
        Invoke-RestMethod -Uri "$MeshBaseUrl/api/v1/admin/agents/$agentId" -Method Delete -Headers $headers | Out-Null
        Write-Host "Deleted Mesh registration for '$agentId'." -ForegroundColor Gray
    } catch {
        if ($_.Exception.Response -and $_.Exception.Response.StatusCode.value__ -eq 404) {
            Write-Host "No Mesh registration exists for '$agentId' — skipping." -ForegroundColor Gray
        } else {
            Write-Host "WARNING: failed to delete Mesh registration for '$agentId': $($_.Exception.Message) — continuing with infra cleanup anyway." -ForegroundColor Yellow
        }
    }

    $sanitizedAgentId = Get-SanitizedName $agentId
    $serviceName = Get-SanitizedName "$DnsNameLabelPrefix-$sanitizedAgentId"

    $existing = (& aws ecs describe-services --region $Region --cluster $ClusterName --services $serviceName 2>$null | ConvertFrom-Json).services | Where-Object { $_.status -eq "ACTIVE" }
    if ($existing) {
        Write-Host "Scaling down and deleting ECS service '$serviceName'..." -ForegroundColor Gray
        aws ecs update-service --region $Region --cluster $ClusterName --service $serviceName --desired-count 0 2>&1 | Out-Null
        aws ecs delete-service --region $Region --cluster $ClusterName --service $serviceName --force 2>&1 | Out-Null
    } else {
        Write-Host "ECS service '$serviceName' does not exist — skipping." -ForegroundColor Gray
    }

    $secretPrefix = "synktron-agents/$Environment/$sanitizedAgentId/"
    $secrets = (& aws secretsmanager list-secrets --region $Region --filters "Key=name,Values=$secretPrefix" 2>$null | ConvertFrom-Json).SecretList
    foreach ($secret in $secrets) {
        aws secretsmanager delete-secret --region $Region --secret-id $secret.Name --force-delete-without-recovery 2>&1 | Out-Null
        Write-Host "Deleted secret '$($secret.Name)'." -ForegroundColor Gray
    }
    if (-not $secrets -or $secrets.Count -eq 0) {
        Write-Host "No secrets found under '$secretPrefix' — skipping." -ForegroundColor Gray
    }
}

if ($DeleteEcrImages) {
    if (-not $AgentEcrRepoName) {
        Write-Host "`nWARNING: -DeleteEcrImages was set but -AgentEcrRepoName is empty — skipping ECR cleanup." -ForegroundColor Yellow
    } else {
        Write-Host "`n=== Deleting ECR repository '$AgentEcrRepoName' ===" -ForegroundColor Cyan
        aws ecr describe-repositories --region $Region --repository-names $AgentEcrRepoName 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) {
            aws ecr delete-repository --region $Region --repository-name $AgentEcrRepoName --force 2>&1 | Out-Null
            Write-Host "Deleted repository '$AgentEcrRepoName' (and every image in it)." -ForegroundColor Gray
        } else {
            Write-Host "Repository '$AgentEcrRepoName' does not exist — skipping." -ForegroundColor Gray
        }
    }
}

Write-Host "`n✅ All 4 fraud-detection agents unregistered and their ECS services/secrets removed." -ForegroundColor Green
