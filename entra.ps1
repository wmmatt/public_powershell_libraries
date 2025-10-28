function Get-EntraJoinStatus {
    <#
    .SYNOPSIS
        Gets the current Entra ID (Azure AD) join status of the device
    
    .DESCRIPTION
        Queries dsregcmd to determine how the device is joined to Entra ID/Azure AD.
        Works correctly when running as SYSTEM by checking registry for user-level joins.
    
    .OUTPUTS
        String - Returns one of: "EntraJoined", "HybridJoined", "DomainJoined", "DomainJoined+EntraRegistered", "EntraRegistered", "NotJoined", or "Unknown"
    
    .EXAMPLE
        Get-EntraJoinStatus
        Returns: "HybridJoined"
    #>
    
    [CmdletBinding()]
    [OutputType([String])]
    param()
    
    try {
        $dsreg = dsregcmd /status
        
        if ($LASTEXITCODE -ne 0) {
            Write-Error "dsregcmd failed to execute"
            return "Unknown"
        }
        
        $azureADJoined = ($dsreg | Select-String "AzureAdJoined\s*:\s*(.*)").Matches.Groups[1].Value.Trim()
        $domainJoined = ($dsreg | Select-String "DomainJoined\s*:\s*(.*)").Matches.Groups[1].Value.Trim()
        $workplaceJoined = ($dsreg | Select-String "WorkplaceJoined\s*:\s*(.*)").Matches.Groups[1].Value.Trim()
        
        $isAzureAD = $azureADJoined -eq "YES"
        $isDomain = $domainJoined -eq "YES"
        $isWorkplace = $workplaceJoined -eq "YES"
        
        if (!$isWorkplace -and $isDomain) {
            $isWorkplace = Test-AnyUserWorkplaceJoined
        }
        
        $statusKey = "$isAzureAD|$isDomain|$isWorkplace"
        
        switch ($statusKey) {
            "True|True|True"  { return "HybridJoined" }
            "True|True|False" { return "HybridJoined" }
            "True|False|True"  { return "EntraJoined" }
            "True|False|False" { return "EntraJoined" }
            "False|True|True" { return "DomainJoined+EntraRegistered" }
            "False|True|False" { return "DomainJoined" }
            "False|False|True" { return "EntraRegistered" }
            "False|False|False" { return "NotJoined" }
            default { return "Unknown" }
        }
        
    } catch {
        Write-Error "Error determining join status: $($_.Exception.Message)"
        return "Unknown"
    }
}

function Test-AnyUserWorkplaceJoined {
    <#
    .SYNOPSIS
        Checks if any user on the machine has WorkplaceJoin (Entra Registered)
        
    .DESCRIPTION
        When running as SYSTEM, dsregcmd only shows machine-level joins.
        This function checks all user registry hives to detect user-level WorkplaceJoin.
    #>
    
    try {
        $userSIDs = Get-ChildItem "Registry::HKEY_USERS" -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'S-1-5-21-' -and $_.Name -notmatch '_Classes$' }
        
        foreach ($userHive in $userSIDs) {
            $wpjPath = "$($userHive.PSPath)\Software\Microsoft\Windows NT\CurrentVersion\WorkplaceJoin"
            
            if (Test-Path $wpjPath -ErrorAction SilentlyContinue) {
                $wpjKeys = Get-ChildItem $wpjPath -ErrorAction SilentlyContinue
                if ($wpjKeys -and $wpjKeys.Count -gt 0) {
                    return $true
                }
            }
        }
        
        return $false
        
    } catch {
        return $false
    }
}

function Test-EntraCompliance {
    <#
    .SYNOPSIS
        Tests if the device's Entra ID join status is compliant
    
    .DESCRIPTION
        Checks if the current device join status matches one of the specified compliant states
    
    .PARAMETER CompliantStates
        Array of join states that are considered compliant.
        Valid values: "EntraJoined", "HybridJoined", "DomainJoined", "DomainJoined+EntraRegistered", "EntraRegistered", "NotJoined"
    
    .OUTPUTS
        Boolean - Returns $true if compliant, $false if not compliant
    
    .EXAMPLE
        Test-EntraCompliance -CompliantStates @("EntraJoined", "HybridJoined")
        Returns: $true (if device is either Entra Joined or Hybrid Joined)
    
    .EXAMPLE
        Test-EntraCompliance -CompliantStates @("HybridJoined")
        Returns: $false (if device is not Hybrid Joined)
    #>
    
    [CmdletBinding()]
    [OutputType([Boolean])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("EntraJoined", "HybridJoined", "DomainJoined", "DomainJoined+EntraRegistered", "EntraRegistered", "NotJoined")]
        [String[]]$CompliantStates
    )
    
    $currentStatus = Get-EntraJoinStatus
    
    if ($currentStatus -in $CompliantStates) {
        return $true
    } else {
        return $false
    }
}
