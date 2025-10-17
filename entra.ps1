function Get-EntraJoinStatus {
    <#
    .SYNOPSIS
        Gets the current Entra ID (Azure AD) join status of the device.
    
    .DESCRIPTION
        Queries dsregcmd to determine how the device is joined to Entra ID/Azure AD.
    
    .OUTPUTS
        String - Returns one of: "EntraJoined", "HybridJoined", "DomainJoined", "EntraRegistered", "NotJoined", or "Unknown"
    
    .EXAMPLE
        Get-EntraJoinStatus
        Returns: "HybridJoined"
    #>
    
    [CmdletBinding()]
    [OutputType([String])]
    param()
    
    try {
        # Run dsregcmd and capture output
        $dsreg = dsregcmd /status
        
        if ($LASTEXITCODE -ne 0) {
            Write-Error "dsregcmd failed to execute"
            return "Unknown"
        }
        
        # Parse relevant fields from dsregcmd output
        $azureADJoined = ($dsreg | Select-String "AzureAdJoined\s*:\s*(.*)").Matches.Groups[1].Value.Trim()
        $domainJoined = ($dsreg | Select-String "DomainJoined\s*:\s*(.*)").Matches.Groups[1].Value.Trim()
        $workplaceJoined = ($dsreg | Select-String "WorkplaceJoined\s*:\s*(.*)").Matches.Groups[1].Value.Trim()
        
        # Determine and return join status
        if ($azureADJoined -eq "YES" -and $domainJoined -eq "YES") {
            return "HybridJoined"
        }
        elseif ($azureADJoined -eq "YES" -and $domainJoined -eq "NO") {
            return "EntraJoined"
        }
        elseif ($domainJoined -eq "YES" -and $azureADJoined -eq "NO") {
            return "DomainJoined"
        }
        elseif ($workplaceJoined -eq "YES") {
            return "EntraRegistered"
        }
        else {
            return "NotJoined"
        }
        
    } catch {
        Write-Error "Error determining join status: $($_.Exception.Message)"
        return "Unknown"
    }
}


function Test-EntraCompliance {
    <#
    .SYNOPSIS
        Tests if the device's Entra ID join status is compliant.
    
    .DESCRIPTION
        Checks if the current device join status matches one of the specified compliant states.
    
    .PARAMETER CompliantStates
        Array of join states that are considered compliant.
        Valid values: "EntraJoined", "HybridJoined", "DomainJoined", "EntraRegistered", "NotJoined"
    
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
        [ValidateSet("EntraJoined", "HybridJoined", "DomainJoined", "EntraRegistered", "NotJoined")]
        [String[]]$CompliantStates
    )
    
    # Get current join status
    $currentStatus = Get-EntraJoinStatus
    
    # Check if current status is in the compliant list
    if ($currentStatus -in $CompliantStates) {
        return $true
    } else {
        return $false
    }
}
