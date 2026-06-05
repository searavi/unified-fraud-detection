param(
    [Parameter(Mandatory)]
    [string]$WorkflowId,

    [string]$OpaUrl = "http://localhost:8181",

    [string[]]$AgentPolicies = @(
        "alert_validation",
        "data_collection",
        "llm_agent",
        "report_generation"
    )
)

$body = @{
    permissive_mode    = $false
    workflow_policies  = @($WorkflowId)
    agent_policies     = $AgentPolicies
    executor_roles     = @("anonymous")
    executor_groups    = @()
    approver_roles     = @("anonymous")
    approver_groups    = @()
    workflow_approvals = @{ $WorkflowId = @{ approved = $true } }
    agent_approvals    = @{}
} | ConvertTo-Json -Depth 5

try {
    Invoke-RestMethod -Uri "$OpaUrl/v1/data" -Method PUT -Body $body -ContentType "application/json"
    Write-Host "Policies loaded."
    Write-Host "  WorkflowId : $WorkflowId"
    Write-Host "  Agents     : $($AgentPolicies -join ', ')"
    Write-Host "  OPA        : $OpaUrl"
} catch {
    Write-Error "Failed to update OPA policies: $_"
    exit 1
}
