function Get-Nuget {
    <#
    .DESCRIPTION
        This function retrieves the NuGet package provider if it is installed on the system.

    .OUTPUTS
        Returns the NuGet package provider object if found, otherwise returns null.

    .EXAMPLE
        Get-Nuget
        This command returns the NuGet package provider if it exists.
    #>

    $nuget = Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue
    return $nuget
}


function Test-Nuget {
    <#
    .DESCRIPTION
        This function checks if the NuGet package provider is installed on the system.

    .OUTPUTS
        Returns a Boolean value:
        - $true if the NuGet package provider is found.
        - $false if it is not found.

    .EXAMPLE
        Test-Nuget
        This command checks for the presence of the NuGet package provider.
    #>

    return [bool](Get-Nuget)
}


function Set-Nuget {
    <#
    .DESCRIPTION
        This function installs the NuGet package provider if it is not already installed.

    .OUTPUTS
        Installs the NuGet package provider and forces the operation to complete.

    .EXAMPLE
        Set-Nuget
        This command installs the NuGet package provider.
    #>

    Install-PackageProvider -Name NuGet -Force -ErrorAction Stop
}


function Set-NugetDesiredState {
    <#
    .DESCRIPTION
        This function ensures the NuGet package provider is installed by checking if it's present
        and installing it if missing.

    .OUTPUTS
        Returns $true if the NuGet package provider is installed; otherwise, attempts installation.

    .EXAMPLE
        Set-NugetDesiredState
        This command checks and installs the NuGet package provider if needed.
    #>

    # Install Nuget if it's missing
    $nuget = Test-Nuget
    if (!$nuget) {
        Set-Nuget
    }

    Test-Nuget
}


function Get-PSWindowsUpdate {
    <#
    .DESCRIPTION
        This function retrieves the PSWindowsUpdate module if it is installed on the system.

    .OUTPUTS
        Returns the PSWindowsUpdate module object if found, otherwise returns null.

    .EXAMPLE
        Get-PSWindowsUpdate
        This command returns the PSWindowsUpdate module if it exists.
    #>

    $pswindowsupdate = Get-Module -Name PSWindowsUpdate -ListAvailable -ErrorAction SilentlyContinue
    return $pswindowsupdate
}


function Test-PSWindowsUpdate {
    <#
    .DESCRIPTION
        This function checks if the PSWindowsUpdate module is installed on the system.

    .OUTPUTS
        Returns a Boolean value:
        - $true if the PSWindowsUpdate module is found.
        - $false if it is not found.

    .EXAMPLE
        Test-PSWindowsUpdate
        This command checks for the presence of the PSWindowsUpdate module.
    #>

    return [bool](Get-PSWindowsUpdate)
}


function Set-PSWindowsUpdate {
    <#
    .DESCRIPTION
        This function installs the PSWindowsUpdate module if it is not already installed.

    .OUTPUTS
        Installs the PSWindowsUpdate module and forces the operation to complete.

    .EXAMPLE
        Set-PSWindowsUpdate
        This command installs the PSWindowsUpdate module.
    #>

    Install-Module -Name PSWindowsUpdate -Force -ErrorAction Stop
}


function Set-PSWindowsUpdateDesiredState {
    <#
    .DESCRIPTION
        This function ensures the PSWindowsUpdate module is installed by checking if it's present
        and installing it if missing. It also imports the module into the current session.

    .OUTPUTS
        Returns $true if the PSWindowsUpdate module is installed; otherwise, attempts installation.

    .EXAMPLE
        Set-PSWindowsUpdateDesiredState
        This command checks and installs the PSWindowsUpdate module if needed.
    #>

    # Check if PSWindowsUpdate module is installed
    $pswindowsupdate = Test-PSWindowsUpdate
    if (!$pswindowsupdate) {
        Set-PSWindowsUpdate
    }
    # Import the module to the current session
    Import-Module -Name PSWindowsUpdate -ErrorAction Stop
    Test-PSWindowsUpdate
}


function Get-WindowsUpdateStats {
    <#
    .DESCRIPTION
        This function retrieves information about the most recent Windows update by using
        PSWindowsUpdate and returns details of the last successful update.

    .OUTPUTS
        Returns an object with the following properties:
        - LastPatchDate (string): The date of the last installed update in MM/dd/yyyy format.
        - PatchName (string): The title of the last installed update.

    .EXAMPLE
        Get-WindowsUpdateStats
        This command retrieves and displays information about the latest installed update.
    #>

    # Collect patch information
    Set-ExecutionPolicy Bypass -Confirm:$false
    # May output this later, but for now just stuffing in a variable
    $output = Set-NugetDesiredState
    $output = Set-PSWindowsUpdateDesiredState
    # The module should already be imported in Set-PSWindowsUpdateDesiredState
    # Proceed to use the module's cmdlets
    # Limit to patches that have a KB to ensure we're looking for real security/OS types of patches
    $installedUpdates = Get-WUHistory | Where-Object { $_.KB -ne '' -and $_.Result -eq 'Succeeded' }
    $lastInstalledUpdate = $installedUpdates | Sort-Object -Property Date | Select-Object -Last 1
    $lastPatchedDate = $lastInstalledUpdate.Date

    # Format the last patched date for output
    $lastPatchedDateFormatted = $lastPatchedDate.ToString("MM/dd/yyyy")

    # Return an object with the results
    return @{
        LastPatchDate = $lastPatchedDateFormatted
        PatchName     = $lastInstalledUpdate.Title
    }
}


function Test-WindowsUpdateState {
    <#
    .DESCRIPTION
        This function checks if the system's last patch date is within an acceptable timeframe.

    .PARAMETER acceptableDays
        Specifies the maximum number of days an endpoint can go without patching.

    .OUTPUTS
        Returns a Boolean value:
        - $true if the last patch date is within the acceptable range.
        - $false if the system is not compliant.

    .EXAMPLE
        Test-WindowsUpdateState
        This command checks if the system is compliant based on the patch date.
    #>

    # Define the maximum number of days an endpoint can go without patching
    $acceptableDays = 45
    $currentDate = Get-Date
    $acceptableDate = $currentDate.AddDays(-$acceptableDays)
    $lastPatchedDate = (Get-WindowsUpdateStats).LastPatchDate

    # Determine if the last patch was installed within the acceptable timeframe
    $isCompliant = $lastPatchedDate -ge $acceptableDate

    return $isCompliant
} 


function Set-WindowsUpdate {
    <#
    .DESCRIPTION
        This function installs all missing Windows updates, except for drivers, without initiating a reboot.

    .OUTPUTS
        Installs all missing patches excluding drivers and suppresses a reboot after installation.

    .EXAMPLE
        Set-WindowsUpdate
        This command installs all applicable updates except drivers without rebooting the system.
    #>

    # Retrieve the list of updates (excluding drivers) that need installation
    $updates = Get-WindowsUpdate
    if ($updates) {
        # Install updates, suppressing reboot
        Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -AutoReboot:$false -ErrorAction Stop
    }
}


function Set-WindowsUpdateDesiredState {
    <#
    .DESCRIPTION
        This function ensures Windows Update compliance by checking for missing updates
        and installing them if necessary, excluding drivers and suppressing a reboot.

    .OUTPUTS
        Returns an object indicating the installation output and compliance status:
        - InstallOutput: Results from attempting the update installation.
        - IsCompliant: $true if the system is compliant, $false otherwise.

    .EXAMPLE
        Set-WindowsUpdateDesiredState
        This command checks for updates, installs them if missing, and returns the compliance status.
    #>

    # Check for missing updates
    $patchCompliant = Test-WindowsUpdateState
    if (!$patchCompliant) {
        # Install all pending updates, excluding drivers, without reboot
        $installOutput = Set-WindowsUpdate
    }
    # Return the compliance state after attempting the update
    $IsCompliant = Test-WindowsUpdateState
    
    # Return an object with the results
    return @{
        InstallOutput = $installOutput
        IsCompliant   = $IsCompliant
    }
}
