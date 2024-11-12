function Get-Nuget {
    $nuget = Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue
    return $nuget
}


function Test-Nuget {
    return [bool](Get-Nuget)
}


function Set-Nuget {
    Install-PackageProvider -Name Nuget -Force -ErrorAction Stop
}


function Set-NugetDesiredState {
    # Install Nuget if it's missing
    $nuget = Test-Nuget
    if (!$nuget) {
        Set-Nuget
    }

    Test-Nuget
}


function Get-PSWindowsUpdate {
    $pswindowsupdate = Get-Module -Name PSWindowsUpdate -ListAvailable -ErrorAction SilentlyContinue
    return $pswindowsupdate
}


function Test-PSWindowsUpdate {
    return [bool](Get-PSWindowsUpdate)
}


function Set-PSWindowsUpdate {
    Install-Module -Name pswindowsupdate -Force -ErrorAction Stop
}


function Set-PSWindowsUpdateDesiredState {
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


function Test-WindowsUpdateStats {
    # Define the maximum number of days an endpoint can go without patching
    $acceptableDays = 45
    $currentDate = Get-Date
    $acceptableDate = $currentDate.AddDays(-$acceptableDays)
    $lastPatchedDate = (Get-WindowsUpdateStats).LastPatchDate

     # Determine if the last patch was installed within the acceptable timeframe
    $isCompliant = $lastPatchedDate -ge $acceptableDate

    return $isCompliant
} 
