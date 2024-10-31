function Get-Nuget {
    $nuget = Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue
    return $nuget
}


function Test-Nuget {
    $nuget = Get-Nuget
    if (!$nuget) {
        return $false
    } else {
        return $true
    }
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
}


function Get-PSWindowsUpdate {
    $pswindowsupdate = Get-Module -Name pswindowsupdate -ErrorAction SilentlyContinue
    return $pswindowsupdate
}


function Test-PSWindowsUpdate {
    $psWindowsUpdate = Get-PSWindowsUpdate
    if (!$psWindowsUpdate) {
        return $false
    } else {
        return $true
    }
}


function Set-PSWindowsUpdate {
    Install-Module -Name pswindowsupdate -Force -ErrorAction Stop
}


function Set-PSWindowsUpdateDesiredState {
    # Install PSWindowsUpdate module if it's missing
    $nuget = Test-PSWindowsUpdate
    if (!$nuget) {
        Set-PSWindowsUpdate
    }
}


function Get-WindowsUpdateStats {
    # Collect patch information
    Set-ExecutionPolicy Bypass
    Set-NugetDesiredState
    Set-PSWindowsUpdateDesiredState
    Import-Module pswindowsupdate -ErrorAction Stop
    # Limit to patches that have a KB to ensure we're looking for real security/OS types of patches
    $installedUpdates = Get-WUHistory | Where-Object { $_.KB -ne '' -and $_.Result -eq 'Succeeded'}
    $lastInstalledUpdate = $installedUpdates | Sort-Object -Property Date | Select-Object -Last 1
    $lastPatchedDate = $lastInstalledUpdate.Date

    # Format the last patched date for output
    $lastPatchedDateFormatted = $lastPatchedDate.ToString("MM/dd/yyyy")

    # Return an object with the results
    return @{
        LastPatchDate = $lastInstalledUpdate.date
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
 