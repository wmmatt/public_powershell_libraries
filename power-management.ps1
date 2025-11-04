<#
.SYNOPSIS
    Windows Power Management Function Library
    
.DESCRIPTION
    Comprehensive PowerShell module for managing Windows power settings including:
    - Sleep/monitor/disk timeouts
    - Power plans
    - Keep-awake functionality
    - Export/import configurations
    - USB selective suspend
    - PCI Express power management
    - Processor power management

    How to Use Presets
        Simple syntax:
        powershellSet-PowerPreset -Preset <PresetName>
        Available Presets
    NeverSleep
        powershellSet-PowerPreset -Preset NeverSleep
        What it does:

        Computer never sleeps (AC or battery)
        Monitor never turns off
        Disk never spins down
        Hibernate disabled

        Best for: Desktops, servers, always-on machines

    Balanced (Windows Default)
        powershellSet-PowerPreset -Preset Balanced
        What it does:

        Sleep after 30 min (plugged in), 15 min (battery)
        Monitor off after 10 min (plugged in), 5 min (battery)
        Disk timeout after 20 min (plugged in), 10 min (battery)

        Best for: Normal use, restoring Windows defaults

    PowerSaver
        powershellSet-PowerPreset -Preset PowerSaver
        What it does:

        Sleep after 15 min (plugged in), 5 min (battery)
        Monitor off after 5 min (plugged in), 2 min (battery)
        Aggressive power saving

        Best for: Maximum battery life on laptops

    HighPerformance
        powershellSet-PowerPreset -Preset HighPerformance
        What it does:

        Never sleeps
        Monitor off after 15 minutes
        Disk never spins down
        USB selective suspend disabled
        Switches to "High performance" power plan

        Best for: Gaming, video editing, performance-critical tasks

    Server
        powershellSet-PowerPreset -Preset Server
        What it does:

        Never sleeps
        Monitor never turns off
        Disk never spins down
        Hibernate completely disabled (frees disk space)
        USB selective suspend disabled

        Best for: Servers, always-on workstations

    Laptop (Smart Mode)
        powershellSet-PowerPreset -Preset Laptop
        What it does:

        Plugged in: Never sleeps, monitor off after 15 min
        Battery: Sleep after 10 min, monitor off after 5 min

        Best for: Laptops - never sleep when docked/plugged in, conserve battery when unplugged

    Presentation
        powershellSet-PowerPreset -Preset Presentation
        What it does:

        Never sleeps
        Monitor never turns off

        Best for: Presentations, demos (TEMPORARY - remember to restore after!)
    
.NOTES
    Version: 1.2 - Fixed Get-PowerPlan parsing bug and improved USB Selective Suspend error handling
    Author: Power Management Library
    Requires: PowerShell 5.1 or later (compatible with 5.1, 7.x)
    Many functions require Administrator privileges
#>

#region Helper Functions

function Test-IsAdmin {
    <#
    .SYNOPSIS
        Check if running as Administrator
    #>
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function ConvertFrom-PowerCfgSeconds {
    <#
    .SYNOPSIS
        Convert powercfg seconds to friendly time
    #>
    param([int]$Seconds)
    
    if ($Seconds -eq 0) { return "Never" }
    if ($Seconds -lt 60) { return "$Seconds seconds" }
    if ($Seconds -lt 3600) { return "$([math]::Round($Seconds/60, 1)) minutes" }
    return "$([math]::Round($Seconds/3600, 1)) hours"
}

#endregion

#region Get Functions

function Get-PowerPlan {
    <#
    .SYNOPSIS
        Get all power plans or the active power plan
        
    .PARAMETER Active
        Only return the active power plan
        
    .EXAMPLE
        Get-PowerPlan
        Lists all power plans
        
    .EXAMPLE
        Get-PowerPlan -Active
        Shows only the active power plan
    #>
    [CmdletBinding()]
    param(
        [switch]$Active
    )
    
    if ($Active) {
        $output = powercfg /getactivescheme
        $guid = ($output -split '\s+')[3]
        $name = ($output -split ':\s*', 2)[1].Trim()
        
        [PSCustomObject]@{
            Name = $name
            GUID = $guid
            IsActive = $true
        }
    } else {
        $plans = powercfg /list | Select-String "Power Scheme GUID"
        
        foreach ($plan in $plans) {
            $line = $plan.ToString()
            
            # Extract GUID (between "GUID:" and the opening parenthesis)
            $guid = $null
            if ($line -match 'Power Scheme GUID:\s*([0-9a-f-]+)') {
                $guid = $Matches[1]
            }
            
            # Extract Name (inside the parentheses)
            $name = $null
            if ($line -match '\(([^)]+)\)') {
                $name = $Matches[1]
            }
            
            $isActive = $line -match '\*$'
            
            [PSCustomObject]@{
                Name = $name
                GUID = $guid
                IsActive = $isActive
            }
        }
    }
}

function Get-SleepTimeout {
    <#
    .SYNOPSIS
        Get current sleep timeout settings
        
    .DESCRIPTION
        Returns sleep timeout for AC and DC (battery) power
        
    .EXAMPLE
        Get-SleepTimeout
    #>
    [CmdletBinding()]
    param()
    
    $activeScheme = (Get-PowerPlan -Active).GUID
    
    $output = powercfg /query $activeScheme SUB_SLEEP STANDBYIDLE
    $acSeconds = [int](($output | Select-String "Current AC Power Setting Index:").ToString().Split()[-1])
    $dcSeconds = [int](($output | Select-String "Current DC Power Setting Index:").ToString().Split()[-1])
    
    [PSCustomObject]@{
        ACPower_Seconds = $acSeconds
        ACPower_Friendly = ConvertFrom-PowerCfgSeconds $acSeconds
        BatteryPower_Seconds = $dcSeconds
        BatteryPower_Friendly = ConvertFrom-PowerCfgSeconds $dcSeconds
    }
}

function Get-MonitorTimeout {
    <#
    .SYNOPSIS
        Get current monitor timeout settings
        
    .EXAMPLE
        Get-MonitorTimeout
    #>
    [CmdletBinding()]
    param()
    
    $activeScheme = (Get-PowerPlan -Active).GUID
    
    $output = powercfg /query $activeScheme SUB_VIDEO VIDEOIDLE
    $acSeconds = [int](($output | Select-String "Current AC Power Setting Index:").ToString().Split()[-1])
    $dcSeconds = [int](($output | Select-String "Current DC Power Setting Index:").ToString().Split()[-1])
    
    [PSCustomObject]@{
        ACPower_Seconds = $acSeconds
        ACPower_Friendly = ConvertFrom-PowerCfgSeconds $acSeconds
        BatteryPower_Seconds = $dcSeconds
        BatteryPower_Friendly = ConvertFrom-PowerCfgSeconds $dcSeconds
    }
}

function Get-DiskTimeout {
    <#
    .SYNOPSIS
        Get current disk timeout settings
        
    .EXAMPLE
        Get-DiskTimeout
    #>
    [CmdletBinding()]
    param()
    
    $activeScheme = (Get-PowerPlan -Active).GUID
    
    $output = powercfg /query $activeScheme SUB_DISK DISKIDLE
    $acSeconds = [int](($output | Select-String "Current AC Power Setting Index:").ToString().Split()[-1])
    $dcSeconds = [int](($output | Select-String "Current DC Power Setting Index:").ToString().Split()[-1])
    
    [PSCustomObject]@{
        ACPower_Seconds = $acSeconds
        ACPower_Friendly = ConvertFrom-PowerCfgSeconds $acSeconds
        BatteryPower_Seconds = $dcSeconds
        BatteryPower_Friendly = ConvertFrom-PowerCfgSeconds $dcSeconds
    }
}

function Get-HibernateTimeout {
    <#
    .SYNOPSIS
        Get current hibernate timeout settings
        
    .EXAMPLE
        Get-HibernateTimeout
    #>
    [CmdletBinding()]
    param()
    
    $activeScheme = (Get-PowerPlan -Active).GUID
    
    $output = powercfg /query $activeScheme SUB_SLEEP HIBERNATEIDLE
    $acSeconds = [int](($output | Select-String "Current AC Power Setting Index:").ToString().Split()[-1])
    $dcSeconds = [int](($output | Select-String "Current DC Power Setting Index:").ToString().Split()[-1])
    
    [PSCustomObject]@{
        ACPower_Seconds = $acSeconds
        ACPower_Friendly = ConvertFrom-PowerCfgSeconds $acSeconds
        BatteryPower_Seconds = $dcSeconds
        BatteryPower_Friendly = ConvertFrom-PowerCfgSeconds $dcSeconds
    }
}

function Get-AllPowerSettings {
    <#
    .SYNOPSIS
        Get comprehensive view of all power settings
        
    .DESCRIPTION
        Returns all major power settings in one object
        
    .EXAMPLE
        Get-AllPowerSettings | Format-List
    #>
    [CmdletBinding()]
    param()
    
    [PSCustomObject]@{
        ActivePowerPlan = (Get-PowerPlan -Active).Name
        SleepTimeout = Get-SleepTimeout
        MonitorTimeout = Get-MonitorTimeout
        DiskTimeout = Get-DiskTimeout
        HibernateTimeout = Get-HibernateTimeout
        HibernateEnabled = (powercfg /availablesleepstates | Select-String "Hibernate") -ne $null
        FastStartupEnabled = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name HiberbootEnabled -ErrorAction SilentlyContinue).HiberbootEnabled -eq 1
    }
}

function Get-USBSelectiveSuspend {
    <#
    .SYNOPSIS
        Get USB selective suspend setting
        
    .EXAMPLE
        Get-USBSelectiveSuspend
    #>
    [CmdletBinding()]
    param()
    
    try {
        $activeScheme = (Get-PowerPlan -Active).GUID
        
        # USB Selective Suspend GUID: 2a737441-1930-4402-8d77-b2bebba308a3
        # SUB_USB GUID: 2a737441-1930-4402-8d77-b2bebba308a3
        # Redirect all output including errors to capture them silently
        $output = powercfg /query $activeScheme 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 2>&1 | Out-String
        
        # Check if command failed or returned invalid parameters
        if ([string]::IsNullOrWhiteSpace($output) -or $output -match "Invalid Parameters" -or $output -match "error" -or $output -match "Element not found") {
            Write-Verbose "USB Selective Suspend query not supported on this system"
            return [PSCustomObject]@{
                ACPower_Enabled = $null
                BatteryPower_Enabled = $null
                Supported = $false
            }
        }
        
        # Try to extract the AC and DC values
        $acLine = $output | Select-String "Current AC Power Setting Index:" -Quiet
        $dcLine = $output | Select-String "Current DC Power Setting Index:" -Quiet
        
        if ($acLine -and $dcLine) {
            $acMatch = [regex]::Match($output, "Current AC Power Setting Index:\s*0x([0-9a-fA-F]+)")
            $dcMatch = [regex]::Match($output, "Current DC Power Setting Index:\s*0x([0-9a-fA-F]+)")
            
            if ($acMatch.Success -and $dcMatch.Success) {
                $acValue = [Convert]::ToInt32($acMatch.Groups[1].Value, 16)
                $dcValue = [Convert]::ToInt32($dcMatch.Groups[1].Value, 16)
                
                return [PSCustomObject]@{
                    ACPower_Enabled = $acValue -eq 1
                    BatteryPower_Enabled = $dcValue -eq 1
                    Supported = $true
                }
            }
        }
        
        # If we got here, parsing failed
        Write-Verbose "Could not parse USB Selective Suspend settings"
        return [PSCustomObject]@{
            ACPower_Enabled = $null
            BatteryPower_Enabled = $null
            Supported = $false
        }
        
    } catch {
        Write-Verbose "Error querying USB Selective Suspend: $_"
        return [PSCustomObject]@{
            ACPower_Enabled = $null
            BatteryPower_Enabled = $null
            Supported = $false
        }
    }
}

#endregion

#region Set Functions

function Set-SleepTimeout {
    <#
    .SYNOPSIS
        Set sleep timeout
        
    .PARAMETER Minutes
        Number of minutes (0 = never)
        
    .PARAMETER ACOnly
        Only set for AC power
        
    .PARAMETER BatteryOnly
        Only set for battery power
        
    .EXAMPLE
        Set-SleepTimeout -Minutes 30
        Set sleep to 30 minutes for both AC and battery
        
    .EXAMPLE
        Set-SleepTimeout -Minutes 0 -ACOnly
        Disable sleep when plugged in only
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateRange(0, 10080)]  # Max 1 week
        [int]$Minutes,
        
        [switch]$ACOnly,
        [switch]$BatteryOnly
    )
    
    if (-not (Test-IsAdmin)) {
        throw "Administrator privileges required"
    }
    
    if ($ACOnly) {
        powercfg /change standby-timeout-ac $Minutes
        Write-Verbose "Set AC sleep timeout to $Minutes minutes"
    }
    elseif ($BatteryOnly) {
        powercfg /change standby-timeout-dc $Minutes
        Write-Verbose "Set battery sleep timeout to $Minutes minutes"
    }
    else {
        powercfg /change standby-timeout-ac $Minutes
        powercfg /change standby-timeout-dc $Minutes
        Write-Verbose "Set sleep timeout to $Minutes minutes (AC and battery)"
    }
}

function Set-MonitorTimeout {
    <#
    .SYNOPSIS
        Set monitor timeout
        
    .PARAMETER Minutes
        Number of minutes (0 = never)
        
    .PARAMETER ACOnly
        Only set for AC power
        
    .PARAMETER BatteryOnly
        Only set for battery power
        
    .EXAMPLE
        Set-MonitorTimeout -Minutes 15
        Monitor turns off after 15 minutes
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateRange(0, 10080)]
        [int]$Minutes,
        
        [switch]$ACOnly,
        [switch]$BatteryOnly
    )
    
    if (-not (Test-IsAdmin)) {
        throw "Administrator privileges required"
    }
    
    if ($ACOnly) {
        powercfg /change monitor-timeout-ac $Minutes
    }
    elseif ($BatteryOnly) {
        powercfg /change monitor-timeout-dc $Minutes
    }
    else {
        powercfg /change monitor-timeout-ac $Minutes
        powercfg /change monitor-timeout-dc $Minutes
    }
}

function Set-DiskTimeout {
    <#
    .SYNOPSIS
        Set disk timeout
        
    .PARAMETER Minutes
        Number of minutes (0 = never)
        
    .EXAMPLE
        Set-DiskTimeout -Minutes 0
        Disable disk timeout
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateRange(0, 10080)]
        [int]$Minutes,
        
        [switch]$ACOnly,
        [switch]$BatteryOnly
    )
    
    if (-not (Test-IsAdmin)) {
        throw "Administrator privileges required"
    }
    
    if ($ACOnly) {
        powercfg /change disk-timeout-ac $Minutes
    }
    elseif ($BatteryOnly) {
        powercfg /change disk-timeout-dc $Minutes
    }
    else {
        powercfg /change disk-timeout-ac $Minutes
        powercfg /change disk-timeout-dc $Minutes
    }
}

function Set-HibernateTimeout {
    <#
    .SYNOPSIS
        Set hibernate timeout
        
    .PARAMETER Minutes
        Number of minutes (0 = never)
        
    .EXAMPLE
        Set-HibernateTimeout -Minutes 0
        Disable hibernate timeout
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateRange(0, 10080)]
        [int]$Minutes,
        
        [switch]$ACOnly,
        [switch]$BatteryOnly
    )
    
    if (-not (Test-IsAdmin)) {
        throw "Administrator privileges required"
    }
    
    if ($ACOnly) {
        powercfg /change hibernate-timeout-ac $Minutes
    }
    elseif ($BatteryOnly) {
        powercfg /change hibernate-timeout-dc $Minutes
    }
    else {
        powercfg /change hibernate-timeout-ac $Minutes
        powercfg /change hibernate-timeout-dc $Minutes
    }
}

function Set-ActivePowerPlan {
    <#
    .SYNOPSIS
        Set the active power plan
        
    .PARAMETER Name
        Name of the power plan (Balanced, High performance, Power saver)
        
    .PARAMETER GUID
        GUID of the power plan
        
    .EXAMPLE
        Set-ActivePowerPlan -Name "High performance"
        
    .EXAMPLE
        Set-ActivePowerPlan -GUID "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
    #>
    [CmdletBinding(DefaultParameterSetName='ByName')]
    param(
        [Parameter(ParameterSetName='ByName')]
        [ValidateSet('Balanced', 'High performance', 'Power saver')]
        [string]$Name,
        
        [Parameter(ParameterSetName='ByGUID')]
        [string]$GUID
    )
    
    if (-not (Test-IsAdmin)) {
        throw "Administrator privileges required"
    }
    
    if ($PSCmdlet.ParameterSetName -eq 'ByName') {
        $plan = Get-PowerPlan | Where-Object { $_.Name -eq $Name }
        if (-not $plan) {
            throw "Power plan '$Name' not found"
        }
        $GUID = $plan.GUID
    }
    
    powercfg /setactive $GUID
    Write-Verbose "Activated power plan: $GUID"
}

function Set-USBSelectiveSuspend {
    <#
    .SYNOPSIS
        Enable or disable USB selective suspend
        
    .PARAMETER Enabled
        Enable USB selective suspend
        
    .PARAMETER Disabled
        Disable USB selective suspend
        
    .EXAMPLE
        Set-USBSelectiveSuspend -Disabled
        Prevents USB devices from being suspended
    #>
    [CmdletBinding()]
    param(
        [Parameter(ParameterSetName='Enable')]
        [switch]$Enabled,
        
        [Parameter(ParameterSetName='Disable')]
        [switch]$Disabled,
        
        [switch]$ACOnly,
        [switch]$BatteryOnly
    )
    
    if (-not (Test-IsAdmin)) {
        throw "Administrator privileges required"
    }
    
    try {
        $activeScheme = (Get-PowerPlan -Active).GUID
        $value = if ($Enabled) { 1 } else { 0 }
        
        # USB Settings GUID: 2a737441-1930-4402-8d77-b2bebba308a3
        # USB Selective Suspend GUID: 48e6b7a6-50f5-4782-a5d4-53bb8f07e226
        $usbGuid = "2a737441-1930-4402-8d77-b2bebba308a3"
        $selectiveSuspendGuid = "48e6b7a6-50f5-4782-a5d4-53bb8f07e226"
        
        if ($ACOnly) {
            $result = powercfg /setacvalueindex $activeScheme $usbGuid $selectiveSuspendGuid $value 2>&1 | Out-String
        }
        elseif ($BatteryOnly) {
            $result = powercfg /setdcvalueindex $activeScheme $usbGuid $selectiveSuspendGuid $value 2>&1 | Out-String
        }
        else {
            $result = powercfg /setacvalueindex $activeScheme $usbGuid $selectiveSuspendGuid $value 2>&1 | Out-String
            powercfg /setdcvalueindex $activeScheme $usbGuid $selectiveSuspendGuid $value 2>&1 | Out-Null
        }
        
        if ($result -match "Invalid Parameters" -or $result -match "error" -or $result -match "Element not found") {
            Write-Warning "USB Selective Suspend setting may not be supported on this system"
        } else {
            powercfg /setactive $activeScheme 2>&1 | Out-Null
            Write-Verbose "USB Selective Suspend $(if($Enabled){'enabled'}else{'disabled'})"
        }
    } catch {
        Write-Warning "Failed to set USB Selective Suspend: $_"
    }
}

#endregion

#region Preset Configurations

function Set-PowerPreset {
    <#
    .SYNOPSIS
        Apply common power configuration presets
        
    .PARAMETER Preset
        The preset to apply
        
    .EXAMPLE
        Set-PowerPreset -Preset NeverSleep
        Computer never sleeps or turns off monitor
        
    .EXAMPLE
        Set-PowerPreset -Preset Server
        Server-optimized settings
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet(
            'NeverSleep',
            'Balanced',
            'PowerSaver',
            'HighPerformance',
            'Server',
            'Laptop',
            'Presentation'
        )]
        [string]$Preset
    )
    
    if (-not (Test-IsAdmin)) {
        throw "Administrator privileges required"
    }
    
    Write-Host "Applying preset: $Preset" -ForegroundColor Cyan
    
    switch ($Preset) {
        'NeverSleep' {
            Set-SleepTimeout -Minutes 0
            Set-MonitorTimeout -Minutes 0
            Set-DiskTimeout -Minutes 0
            Set-HibernateTimeout -Minutes 0
            Write-Host "✓ Never Sleep preset applied" -ForegroundColor Green
        }
        
        'Balanced' {
            Set-ActivePowerPlan -Name "Balanced"
            Set-SleepTimeout -Minutes 30 -ACOnly
            Set-SleepTimeout -Minutes 15 -BatteryOnly
            Set-MonitorTimeout -Minutes 10 -ACOnly
            Set-MonitorTimeout -Minutes 5 -BatteryOnly
            Set-DiskTimeout -Minutes 20 -ACOnly
            Set-DiskTimeout -Minutes 10 -BatteryOnly
            Write-Host "✓ Balanced preset applied" -ForegroundColor Green
        }
        
        'PowerSaver' {
            Set-ActivePowerPlan -Name "Power saver"
            Set-SleepTimeout -Minutes 15 -ACOnly
            Set-SleepTimeout -Minutes 5 -BatteryOnly
            Set-MonitorTimeout -Minutes 5 -ACOnly
            Set-MonitorTimeout -Minutes 2 -BatteryOnly
            Set-DiskTimeout -Minutes 10 -ACOnly
            Set-DiskTimeout -Minutes 5 -BatteryOnly
            Write-Host "✓ Power Saver preset applied" -ForegroundColor Green
        }
        
        'HighPerformance' {
            Set-ActivePowerPlan -Name "High performance"
            Set-SleepTimeout -Minutes 0
            Set-MonitorTimeout -Minutes 15
            Set-DiskTimeout -Minutes 0
            Set-USBSelectiveSuspend -Disabled -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            Write-Host "✓ High Performance preset applied" -ForegroundColor Green
        }
        
        'Server' {
            Set-SleepTimeout -Minutes 0
            Set-MonitorTimeout -Minutes 0
            Set-DiskTimeout -Minutes 0
            Set-HibernateTimeout -Minutes 0
            Set-USBSelectiveSuspend -Disabled -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            Disable-Hibernate
            Write-Host "✓ Server preset applied" -ForegroundColor Green
        }
        
        'Laptop' {
            Set-SleepTimeout -Minutes 0 -ACOnly
            Set-SleepTimeout -Minutes 10 -BatteryOnly
            Set-MonitorTimeout -Minutes 15 -ACOnly
            Set-MonitorTimeout -Minutes 5 -BatteryOnly
            Set-DiskTimeout -Minutes 20 -ACOnly
            Set-DiskTimeout -Minutes 5 -BatteryOnly
            Write-Host "✓ Laptop preset applied (never sleep when plugged in)" -ForegroundColor Green
        }
        
        'Presentation' {
            Set-SleepTimeout -Minutes 0
            Set-MonitorTimeout -Minutes 0
            Write-Host "✓ Presentation preset applied (revert when done!)" -ForegroundColor Green
        }
    }
}

#endregion

#region Hibernate Management

function Enable-Hibernate {
    <#
    .SYNOPSIS
        Enable hibernate functionality
        
    .EXAMPLE
        Enable-Hibernate
    #>
    [CmdletBinding()]
    param()
    
    if (-not (Test-IsAdmin)) {
        throw "Administrator privileges required"
    }
    
    powercfg /hibernate on
    Write-Host "✓ Hibernate enabled" -ForegroundColor Green
}

function Disable-Hibernate {
    <#
    .SYNOPSIS
        Disable hibernate and delete hiberfil.sys
        
    .EXAMPLE
        Disable-Hibernate
    #>
    [CmdletBinding()]
    param()
    
    if (-not (Test-IsAdmin)) {
        throw "Administrator privileges required"
    }
    
    powercfg /hibernate off
    Write-Host "✓ Hibernate disabled (hiberfil.sys deleted)" -ForegroundColor Green
}

function Get-HibernateFileSize {
    <#
    .SYNOPSIS
        Get size of hiberfil.sys
        
    .EXAMPLE
        Get-HibernateFileSize
    #>
    [CmdletBinding()]
    param()
    
    $hiberFile = "$env:SystemDrive\hiberfil.sys"
    
    if (Test-Path $hiberFile) {
        $size = (Get-Item $hiberFile -Force).Length
        $sizeGB = [math]::Round($size / 1GB, 2)
        
        [PSCustomObject]@{
            Path = $hiberFile
            SizeBytes = $size
            SizeGB = $sizeGB
            Exists = $true
        }
    } else {
        [PSCustomObject]@{
            Path = $hiberFile
            SizeBytes = 0
            SizeGB = 0
            Exists = $false
        }
    }
}

#endregion

#region Keep Awake

function Start-KeepAwake {
    <#
    .SYNOPSIS
        Prevent computer from sleeping temporarily
        
    .DESCRIPTION
        Uses Windows API to prevent sleep without changing power settings.
        Press Ctrl+C to stop and restore normal sleep behavior.
        
    .PARAMETER KeepDisplayOn
        Also prevent display from turning off
        
    .EXAMPLE
        Start-KeepAwake
        Prevents sleep until stopped
        
    .EXAMPLE
        Start-KeepAwake -KeepDisplayOn
        Prevents sleep and keeps display on
    #>
    [CmdletBinding()]
    param(
        [switch]$KeepDisplayOn
    )
    
    Add-Type @'
using System;
using System.Runtime.InteropServices;

public class SleepUtil {
    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern uint SetThreadExecutionState(uint esFlags);
    
    public const uint ES_CONTINUOUS = 0x80000000;
    public const uint ES_SYSTEM_REQUIRED = 0x00000001;
    public const uint ES_DISPLAY_REQUIRED = 0x00000002;
}
'@
    
    try {
        Write-Host "`n╔════════════════════════════════════════╗" -ForegroundColor Cyan
        Write-Host "║     Keep-Awake Mode Active             ║" -ForegroundColor Cyan
        Write-Host "╚════════════════════════════════════════╝" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Computer sleep is PREVENTED" -ForegroundColor Green
        Write-Host "Press Ctrl+C to stop`n" -ForegroundColor Yellow
        
        $flags = [SleepUtil]::ES_CONTINUOUS -bor [SleepUtil]::ES_SYSTEM_REQUIRED
        
        if ($KeepDisplayOn) {
            $flags = $flags -bor [SleepUtil]::ES_DISPLAY_REQUIRED
            Write-Host "Display will also stay on`n" -ForegroundColor Green
        }
        
        [SleepUtil]::SetThreadExecutionState($flags) | Out-Null
        
        while ($true) {
            Start-Sleep -Seconds 60
            Write-Host "$(Get-Date -Format 'HH:mm:ss') - Still awake..." -ForegroundColor Gray
        }
    }
    finally {
        [SleepUtil]::SetThreadExecutionState([SleepUtil]::ES_CONTINUOUS) | Out-Null
        Write-Host "`nKeep-awake stopped. Normal sleep behavior restored." -ForegroundColor Green
    }
}

#endregion

#region Export/Import

function Export-PowerConfiguration {
    <#
    .SYNOPSIS
        Export current power configuration to file
        
    .PARAMETER Path
        Output file path
        
    .EXAMPLE
        Export-PowerConfiguration -Path "C:\Backup\power-config.json"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )
    
    $config = @{
        ExportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        ActivePowerPlan = Get-PowerPlan -Active
        SleepTimeout = Get-SleepTimeout
        MonitorTimeout = Get-MonitorTimeout
        DiskTimeout = Get-DiskTimeout
        HibernateTimeout = Get-HibernateTimeout
        USBSelectiveSuspend = Get-USBSelectiveSuspend
        HibernateEnabled = (powercfg /availablesleepstates | Select-String "Hibernate") -ne $null
    }
    
    $config | ConvertTo-Json -Depth 10 | Set-Content -Path $Path
    Write-Host "✓ Configuration exported to: $Path" -ForegroundColor Green
}

function Import-PowerConfiguration {
    <#
    .SYNOPSIS
        Import and apply power configuration from file
        
    .PARAMETER Path
        Input file path
        
    .EXAMPLE
        Import-PowerConfiguration -Path "C:\Backup\power-config.json"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )
    
    if (-not (Test-IsAdmin)) {
        throw "Administrator privileges required"
    }
    
    if (-not (Test-Path $Path)) {
        throw "Configuration file not found: $Path"
    }
    
    $config = Get-Content $Path | ConvertFrom-Json
    
    Write-Host "Importing configuration from: $Path" -ForegroundColor Cyan
    Write-Host "Exported on: $($config.ExportDate)" -ForegroundColor Gray
    
    # Apply settings
    Set-SleepTimeout -Minutes ($config.SleepTimeout.ACPower_Seconds / 60) -ACOnly
    Set-SleepTimeout -Minutes ($config.SleepTimeout.BatteryPower_Seconds / 60) -BatteryOnly
    
    Set-MonitorTimeout -Minutes ($config.MonitorTimeout.ACPower_Seconds / 60) -ACOnly
    Set-MonitorTimeout -Minutes ($config.MonitorTimeout.BatteryPower_Seconds / 60) -BatteryOnly
    
    Set-DiskTimeout -Minutes ($config.DiskTimeout.ACPower_Seconds / 60) -ACOnly
    Set-DiskTimeout -Minutes ($config.DiskTimeout.BatteryPower_Seconds / 60) -BatteryOnly
    
    Write-Host "✓ Configuration imported and applied" -ForegroundColor Green
}

#endregion

#region Display/Reporting

function Show-PowerSettings {
    <#
    .SYNOPSIS
        Display all power settings in a formatted view
        
    .EXAMPLE
        Show-PowerSettings
    #>
    [CmdletBinding()]
    param()
    
    Write-Host "`n╔════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║     Current Power Settings             ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════╝" -ForegroundColor Cyan
    
    $activePlan = Get-PowerPlan -Active
    Write-Host "`nActive Power Plan: " -NoNewline
    Write-Host $activePlan.Name -ForegroundColor Green
    
    $sleep = Get-SleepTimeout
    Write-Host "`nSleep Timeout:" -ForegroundColor White
    Write-Host "  AC Power:      $($sleep.ACPower_Friendly)" -ForegroundColor Gray
    Write-Host "  Battery Power: $($sleep.BatteryPower_Friendly)" -ForegroundColor Gray
    
    $monitor = Get-MonitorTimeout
    Write-Host "`nMonitor Timeout:" -ForegroundColor White
    Write-Host "  AC Power:      $($monitor.ACPower_Friendly)" -ForegroundColor Gray
    Write-Host "  Battery Power: $($monitor.BatteryPower_Friendly)" -ForegroundColor Gray
    
    $disk = Get-DiskTimeout
    Write-Host "`nDisk Timeout:" -ForegroundColor White
    Write-Host "  AC Power:      $($disk.ACPower_Friendly)" -ForegroundColor Gray
    Write-Host "  Battery Power: $($disk.BatteryPower_Friendly)" -ForegroundColor Gray
    
    $usb = Get-USBSelectiveSuspend
    Write-Host "`nUSB Selective Suspend:" -ForegroundColor White
    if ($usb.Supported) {
        Write-Host "  AC Power:      $(if($usb.ACPower_Enabled){'Enabled'}else{'Disabled'})" -ForegroundColor Gray
        Write-Host "  Battery Power: $(if($usb.BatteryPower_Enabled){'Enabled'}else{'Disabled'})" -ForegroundColor Gray
    } else {
        Write-Host "  Not available on this system" -ForegroundColor Yellow
    }
    
    $hiberFile = Get-HibernateFileSize
    Write-Host "`nHibernate:" -ForegroundColor White
    Write-Host "  Status: $(if($hiberFile.Exists){'Enabled'}else{'Disabled'})" -ForegroundColor Gray
    if ($hiberFile.Exists) {
        Write-Host "  File Size: $($hiberFile.SizeGB) GB" -ForegroundColor Gray
    }
    
    Write-Host ""
}

#endregion
