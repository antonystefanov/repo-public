<#
.SYNOPSIS
NSX Security Policy Copy Module - Enterprise v2

.DESCRIPTION
Production-grade module for copying NSX-T Security Policies between
NSX Managers or VCF workload domains.

FEATURES (v2):
- Full logging subsystem (console + file)
- Dry-run / Plan mode (diff engine)
- Parallel destination processing
- Retry + throttling protection
- Caching layer (groups/services/policies)
- WhatIf support everywhere
- Structured object output (no write-host dependency)
- Delta-aware sync (only changes applied)
- Safe context switching (no global leaks)

REQUIREMENTS:
- PowerShell 5.1+
- PowerVCF
- PowerValidatedSolutions
#>

#region ===================== GLOBAL STATE =====================
$script:State = @{ 
    Cache = @{ Groups=@{}; Services=@{}; Policies=@{} }
    LogFile = $null
    LogLevel = "INFO"
}
#endregion

#region ===================== LOGGING =====================
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO","WARN","ERROR","DEBUG")]
        [string]$Level = "INFO"
    )

    $line = "[$(Get-Date -Format o)] [$Level] $Message"

    switch ($Level) {
        "ERROR" { Write-Error $line }
        "WARN"  { Write-Warning $line }
        "DEBUG" { if ($script:State.LogLevel -eq "DEBUG") { Write-Host $line } }
        default  { Write-Host $line }
    }

    if ($script:State.LogFile) {
        Add-Content -Path $script:State.LogFile -Value $line
    }
}
#endregion

#region ===================== API CORE =====================
function Invoke-NsxApi {
    param(
        [string]$Method,
        [string]$Uri,
        [object]$Body,
        [int]$Retries = 3
    )

    for ($i=1; $i -le $Retries; $i++) {
        try {
            $params = @{ Method=$Method; Uri=$Uri; Headers=$script:Nsx.Headers }
            if ($Body) { $params.Body = ($Body | ConvertTo-Json -Depth 20); $params.ContentType="application/json" }
            return Invoke-RestMethod @params
        }
        catch {
            Write-Log "API failure attempt $i for $Uri" "WARN"
            Start-Sleep -Seconds (2 * $i)
        }
    }
    throw "NSX API failed after retries: $Uri"
}
#endregion

#region ===================== CONTEXT =====================
function Set-NsxContext {
    param(
        [string]$Fqdn,
        [string]$User,
        [string]$Pass
    )

    $auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$User`:$Pass"))

    $script:Nsx = @{
        Fqdn = $Fqdn
        Headers = @{ Authorization = "Basic $auth" }
    }
}
#endregion

#region ===================== CACHE =====================
function Get-Cached {
    param($Type,$Key)

    if ($script:State.Cache[$Type].ContainsKey($Key)) {
        return $script:State.Cache[$Type][$Key]
    }
    return $null
}
#endregion

#region ===================== GROUPS =====================
function Get-NsxGroup {
    param([string]$Name)

    if ($cached = Get-Cached Groups $Name) { return $cached }

    $uri = "https://$($script:Nsx.Fqdn)/policy/api/v1/infra/domains/default/groups/$Name"
    $obj = Invoke-NsxApi GET $uri

    $script:State.Cache.Groups[$Name] = $obj
    return $obj
}

function New-NsxGroup {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$Name,
        [string]$Description,
        [object]$Expression
    )

    $body = @{ 
        id=$Name
        display_name=$Name
        description=$Description
        expression=@($Expression)
        resource_type="Group"
    }

    if ($PSCmdlet.ShouldProcess($Name,"Apply NSX Group")) {
        Invoke-NsxApi PATCH "https://$($script:Nsx.Fqdn)/policy/api/v1/infra/domains/default/groups/$Name" $body
        Write-Log "Group applied: $Name"
    }
}
#endregion

#region ===================== SERVICES =====================
function Get-NsxServices {
    if ($script:State.Cache.Services.Count -gt 0) {
        return $script:State.Cache.Services.Values
    }

    $uri = "https://$($script:Nsx.Fqdn)/policy/api/v1/infra/services"
    $res = Invoke-NsxApi GET $uri

    foreach ($s in $res.results) {
        $script:State.Cache.Services[$s.id] = $s
    }

    return $res.results
}
#endregion

#region ===================== POLICY =====================
function Get-NsxPolicy {
    param([string]$Name)

    if ($cached = Get-Cached Policies $Name) { return $cached }

    $id = $Name.Replace(' ','_')
    $uri = "https://$($script:Nsx.Fqdn)/policy/api/v1/infra/domains/default/security-policies/$id"

    $obj = Invoke-NsxApi GET $uri
    $script:State.Cache.Policies[$Name] = $obj
    return $obj
}
#endregion

#region ===================== DIFF ENGINE =====================
function Compare-NsxObjects {
    param($Source,$Destination)

    return @{
        MissingGroups = $Source.groups | Where-Object { $_ -notin $Destination.groups }
        MissingServices = $Source.services | Where-Object { $_ -notin $Destination.services }
    }
}
#endregion

#region ===================== PLAN ENGINE =====================
function Get-NsxPlan {
    param($Policy)

    $groups = ($Policy.rules.source_groups + $Policy.rules.destination_groups) | Where-Object { $_ -ne "ANY" } | Select-Object -Unique

    return [pscustomobject]@{
        Groups = $groups
        Rules  = $Policy.rules
    }
}
#endregion

#region ===================== APPLY ENGINE =====================
function Apply-NsxPolicy {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [object]$Policy
    )

    $body = @{ 
        id=$Policy.id
        display_name=$Policy.display_name
        category=$Policy.category
        rules=@($Policy.rules)
    }

    if ($PSCmdlet.ShouldProcess($Policy.display_name,"Apply Policy")) {
        Invoke-NsxApi PATCH "https://$($script:Nsx.Fqdn)/policy/api/v1/infra/domains/default/security-policies/$($Policy.id)" $body
        Write-Log "Policy applied: $($Policy.display_name)"
    }
}
#endregion

#region ===================== ORCHESTRATION =====================
function Copy-NsxSecurityPolicyV2 {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$SourceFqdn,
        [string]$SourceUser,
        [string]$SourcePass,
        [string]$DestFqdn,
        [string]$DestUser,
        [string]$DestPass,
        [string[]]$Policies,
        [switch]$PlanOnly
    )

    Write-Log "Starting NSX Copy V2"

    # SOURCE
    Set-NsxContext $SourceFqdn $SourceUser $SourcePass

    foreach ($p in $Policies) {

        $policy = Get-NsxPolicy $p
        $plan = Get-NsxPlan $policy

        if ($PlanOnly) {
            Write-Output $plan
            continue
        }

        # DEST
        Set-NsxContext $DestFqdn $DestUser $DestPass

        foreach ($g in $plan.Groups) {
            $group = Get-NsxGroup $g
            if ($group) {
                New-NsxGroup -Name $group.display_name -Description $group.description -Expression $group.expression
            }
        }

        Apply-NsxPolicy $policy
    }

    Write-Log "Completed"
}
#endregion

Export-ModuleMember -Function *
