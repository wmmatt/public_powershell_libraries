#Requires -Version 5.1

<#
.SYNOPSIS
Installation-Library.ps1 - Comprehensive software installation library for Windows

.DESCRIPTION
This library provides robust installation functions for EXE and MSI installers with:
- Automatic file type detection
- Comprehensive error handling and logging
- Child process monitoring for stub installers
- MSI property injection and transform support
- Installation verification
- Download from URLs with hash verification

.FUNCTIONS
- Install-Package: Auto-detects installer type and installs
- Install-Exe: Install EXE files with advanced monitoring
- Install-Msi: Install MSI files with property injection
- Get-InstallFileType: Detect installer type
- Get-ApplicationInstallStatus: Verify app installation
- Get-InstalledService: Verify service installation

.AUTHOR
Created for robust, production-ready software deployment

.VERSION
2.0
#>

# ============================================================================
# PRIVATE HELPER FUNCTIONS
# ============================================================================

Function Write-InstallLog {
    <#
    .SYNOPSIS
    Internal logging function used by all install functions
    #>
    param(
        [Parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "WARNING", "ERROR", "VERBOSE")]
        [string]$Level = "INFO",
        
        [Parameter(Mandatory=$true)]
        [string]$LogFile
    )
    
    # Skip empty messages
    if ([string]::IsNullOrWhiteSpace($Message)) {
        return
    }
    
    $logMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
    Add-Content -Path $LogFile -Value $logMessage
    
    switch ($Level) {
        "ERROR" { Write-Error $Message }
        "WARNING" { Write-Warning $Message }
        "VERBOSE" { Write-Verbose $Message }
        default { Write-Host $Message }
    }
}

Function Get-FileFromUrl {
    <#
    .SYNOPSIS
    Internal function to download files with progress and hash verification
    #>
    param(
        [string]$Url,
        [string]$DestinationPath,
        [string]$ExpectedHash,
        [string]$LogFile
    )
    
    Write-InstallLog -Message "Downloading file from: $Url" -LogFile $LogFile
    Write-InstallLog -Message "Destination: $DestinationPath" -LogFile $LogFile
    
    try {
        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.Add("user-agent", "PowerShell Install Script")
        
        # Register progress event
        Register-ObjectEvent -InputObject $webClient -EventName DownloadProgressChanged -SourceIdentifier WebClient.DownloadProgressChanged -Action {
            Write-Progress -Activity "Downloading" -Status "$($EventArgs.ProgressPercentage)% Complete" -PercentComplete $EventArgs.ProgressPercentage
        } | Out-Null
        
        $webClient.DownloadFile($Url, $DestinationPath)
        
        Unregister-Event -SourceIdentifier WebClient.DownloadProgressChanged -ErrorAction SilentlyContinue
        Write-Progress -Activity "Downloading" -Completed
        
        Write-InstallLog -Message "Download completed successfully" -LogFile $LogFile
        
        # Verify file exists
        if (!(Test-Path -Path $DestinationPath)) {
            throw "Downloaded file not found at: $DestinationPath"
        }
        
        # Verify hash if provided
        if ($ExpectedHash) {
            Write-InstallLog -Message "Verifying file hash..." -LogFile $LogFile
            $actualHash = (Get-FileHash -Path $DestinationPath -Algorithm SHA256).Hash
            
            if ($actualHash -ne $ExpectedHash) {
                Write-InstallLog -Message "Hash mismatch! Expected: $ExpectedHash, Actual: $actualHash" -Level "ERROR" -LogFile $LogFile
                throw "File hash verification failed. File may be corrupted or tampered with."
            }
            Write-InstallLog -Message "Hash verification passed" -LogFile $LogFile
        }
        
        return $true
    } catch {
        Write-InstallLog -Message "Download failed: $_" -Level "ERROR" -LogFile $LogFile
        throw
    }
}

# ============================================================================
# PUBLIC FUNCTIONS
# ============================================================================

Function Get-InstallFileType {
    <#
    .SYNOPSIS
    Detects whether a file is an EXE or MSI installer
    
    .DESCRIPTION
    Examines file extension and validates file signature to determine installer type
    
    .PARAMETER Path
    Path to the installer file (can be URL or local path)
    
    .EXAMPLE
    Get-InstallFileType -Path "C:\installer.msi"
    Returns: "MSI"
    
    .EXAMPLE
    Get-InstallFileType -Path "https://example.com/app.exe"
    Returns: "EXE"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )
    
    # If URL, extract filename from URL
    if ($Path -match "^https?://") {
        $fileName = [System.IO.Path]::GetFileName($Path.Split('?')[0])
    } else {
        $fileName = [System.IO.Path]::GetFileName($Path)
    }
    
    $extension = [System.IO.Path]::GetExtension($fileName).ToLower()
    
    switch ($extension) {
        ".msi" { return "MSI" }
        ".exe" { return "EXE" }
        default {
            # If no clear extension, try to detect from file if local
            if (Test-Path -Path $Path) {
                try {
                    # Read first few bytes to check magic number
                    $bytes = [System.IO.File]::ReadAllBytes($Path) | Select-Object -First 4
                    
                    # MSI files start with D0 CF 11 E0 (OLE Compound File)
                    if ($bytes[0] -eq 0xD0 -and $bytes[1] -eq 0xCF -and $bytes[2] -eq 0x11 -and $bytes[3] -eq 0xE0) {
                        return "MSI"
                    }
                    
                    # EXE files start with MZ (0x4D 0x5A)
                    if ($bytes[0] -eq 0x4D -and $bytes[1] -eq 0x5A) {
                        return "EXE"
                    }
                } catch {
                    # If we can't read the file, fall back to extension
                }
            }
            
            throw "Unable to determine file type for: $Path. Must be .exe or .msi"
        }
    }
}

Function Install-Package {
    <#
    .SYNOPSIS
    Auto-detects installer type (EXE or MSI) and installs the package
    
    .DESCRIPTION
    Automatically detects whether the installer is an EXE or MSI and routes to the appropriate
    install function. Supports all parameters from both Install-Exe and Install-Msi.
    
    .PARAMETER Source
    URL or local file path to the installer (EXE or MSI)
    
    .PARAMETER Arguments
    Arguments for EXE installers (ignored if MSI detected)
    
    .PARAMETER Properties
    Properties hashtable for MSI installers (ignored if EXE detected)
    
    .PARAMETER ExpectedAppName
    Application name as it appears in Add/Remove Programs for verification
    
    .PARAMETER VerifyInstallation
    Use Get-ApplicationInstallStatus to verify the app installed successfully
    
    .EXAMPLE
    Install-Package -Source "app.msi" -Properties @{INSTALLDIR="C:\Apps"} -VerifyInstallation $true
    
    .EXAMPLE
    Install-Package -Source "app.exe" -Arguments "/S" -ExpectedAppName "MyApp"
    
    .EXAMPLE
    Install-Package -Source "https://example.com/installer.msi" -ExpectedHash "ABC123..."
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Source,
        
        # EXE-specific parameters
        [Parameter(Mandatory = $false)]
        [string]$Arguments,
        
        # MSI-specific parameters
        [Parameter(Mandatory = $false)]
        [hashtable]$Properties,
        
        [Parameter(Mandatory = $false)]
        [string]$TransformFile,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("", "v", "warningmessages", "e", "errormessages", "i", "statusmessages", "o", "outofdiskspace", 
                     "a", "actionstart", "r", "actionspecificrecords", "u", "userrequests", "c", "initialUIparameters",
                     "m", "outofmemory", "p", "properties", "voicewarmup", "voicewarmupx")]
        [string]$MsiLogLevel = "voicewarmup",
        
        # Common parameters
        [Parameter(Mandatory = $false)]
        [string]$ExpectedAppName,
        
        [Parameter(Mandatory = $false)]
        [string]$DownloadPath = $env:TEMP,
        
        [Parameter(Mandatory = $false)]
        [string]$ExpectedHash,
        
        [Parameter(Mandatory = $false)]
        [int[]]$ValidExitCodes,
        
        [Parameter(Mandatory = $false)]
        [int]$TimeoutMinutes = 30,
        
        [Parameter(Mandatory = $false)]
        [boolean]$VerifyInstallation = $false,
        
        [Parameter(Mandatory = $false)]
        [boolean]$KeepDownloadedFile = $false,
        
        [Parameter(Mandatory = $false)]
        [string]$LogPath = "$env:TEMP\InstallLogs"
    )
    
    Write-Host "=== Auto-Detecting Installer Type ===" -ForegroundColor Cyan
    
    try {
        $fileType = Get-InstallFileType -Path $Source
        Write-Host "Detected installer type: $fileType" -ForegroundColor Green
        Write-Host ""
        
        # Route to appropriate function based on type
        if ($fileType -eq "MSI") {
            # Build parameters for Install-Msi
            $msiParams = @{
                Source = $Source
                ExpectedAppName = $ExpectedAppName
                DownloadPath = $DownloadPath
                ExpectedHash = $ExpectedHash
                TimeoutMinutes = $TimeoutMinutes
                VerifyInstallation = $VerifyInstallation
                KeepDownloadedFile = $KeepDownloadedFile
                LogPath = $LogPath
                MsiLogLevel = $MsiLogLevel
            }
            
            if ($Properties) { $msiParams.Properties = $Properties }
            if ($TransformFile) { $msiParams.TransformFile = $TransformFile }
            if ($ValidExitCodes) { $msiParams.ValidExitCodes = $ValidExitCodes }
            
            return Install-Msi @msiParams
            
        } elseif ($fileType -eq "EXE") {
            # Build parameters for Install-Exe
            $exeParams = @{
                Source = $Source
                Arguments = $Arguments
                ExpectedAppName = $ExpectedAppName
                DownloadPath = $DownloadPath
                ExpectedHash = $ExpectedHash
                TimeoutMinutes = $TimeoutMinutes
                VerifyInstallation = $VerifyInstallation
                KeepDownloadedFile = $KeepDownloadedFile
                LogPath = $LogPath
            }
            
            if ($ValidExitCodes) { $exeParams.ValidExitCodes = $ValidExitCodes }
            
            return Install-Exe @exeParams
        }
        
    } catch {
        Write-Error "Install-Package failed: $_"
        throw
    }
}

Function Install-Msi {
    <#
    .SYNOPSIS
    Install MSI files with comprehensive error handling and logging
    
    .DESCRIPTION
    Robust MSI installation with property injection, transform support, detailed logging,
    and verification. Uses msiexec.exe with proper arguments and exit code handling.
    
    .PARAMETER Source
    URL or local file path to the MSI installer
    
    .PARAMETER Properties
    Hashtable of MSI properties to inject (e.g., @{INSTALLDIR="C:\Apps"; ALLUSERS=1})
    
    .PARAMETER TransformFile
    Path to MST transform file
    
    .PARAMETER MsiLogLevel
    MSI logging verbosity. Default: "voicewarmup" (verbose). Common values:
    - "" (no logging)
    - "v" (verbose)
    - "voicewarmup" (everything - recommended)
    
    .PARAMETER ValidExitCodes
    Array of exit codes that indicate successful installation. 
    Default: @(0, 3010, 1641)
    - 0 = Success
    - 3010 = Success, reboot required
    - 1641 = Success, reboot initiated
    
    .PARAMETER ExpectedAppName
    Application name as it appears in Add/Remove Programs for verification
    
    .PARAMETER VerifyInstallation
    Verify the app installed successfully using Get-ApplicationInstallStatus
    
    .PARAMETER TimeoutMinutes
    Maximum time to wait for installation. Default: 30 minutes
    
    .EXAMPLE
    Install-Msi -Source "app.msi" -Properties @{INSTALLDIR="C:\Apps"; ALLUSERS=1}
    
    .EXAMPLE
    Install-Msi -Source "https://example.com/app.msi" -TransformFile "custom.mst" -VerifyInstallation $true
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Source,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Properties = @{},
        
        [Parameter(Mandatory = $false)]
        [string]$TransformFile,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("", "v", "warningmessages", "e", "errormessages", "i", "statusmessages", "o", "outofdiskspace", 
                     "a", "actionstart", "r", "actionspecificrecords", "u", "userrequests", "c", "initialUIparameters",
                     "m", "outofmemory", "p", "properties", "voicewarmup", "voicewarmupx")]
        [string]$MsiLogLevel = "voicewarmup",
        
        [Parameter(Mandatory = $false)]
        [string]$ExpectedAppName,
        
        [Parameter(Mandatory = $false)]
        [string]$DownloadPath = $env:TEMP,
        
        [Parameter(Mandatory = $false)]
        [string]$ExpectedHash,
        
        [Parameter(Mandatory = $false)]
        [int[]]$ValidExitCodes = @(0, 3010, 1641),
        
        [Parameter(Mandatory = $false)]
        [int]$TimeoutMinutes = 30,
        
        [Parameter(Mandatory = $false)]
        [boolean]$VerifyInstallation = $false,
        
        [Parameter(Mandatory = $false)]
        [boolean]$KeepDownloadedFile = $false,
        
        [Parameter(Mandatory = $false)]
        [string]$LogPath = "$env:TEMP\InstallLogs",
        
        [Parameter(Mandatory = $false)]
        [boolean]$NoReboot = $true
    )
    
    # Initialize variables
    $isUrl = $false
    $localMsiPath = ""
    $downloadedFile = $false
    $installSuccess = $false
    $logFile = ""
    $msiLogFile = ""
    
    # Create log directory
    if (!(Test-Path -Path $LogPath)) {
        try {
            New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
        } catch {
            Write-Warning "Could not create log directory: $LogPath. Using $env:TEMP"
            $LogPath = $env:TEMP
        }
    }
    
    # Create timestamped log file
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $logFile = Join-Path -Path $LogPath -ChildPath "InstallMsi_$timestamp.log"
    $msiLogFile = Join-Path -Path $LogPath -ChildPath "MsiInstall_$timestamp.log"
    
    Write-InstallLog -Message "========== MSI Installation Started ==========" -LogFile $logFile
    Write-InstallLog -Message "Source: $Source" -LogFile $logFile
    Write-InstallLog -Message "Properties: $($Properties | ConvertTo-Json -Compress)" -LogFile $logFile
    
    try {
        # Determine if source is URL or local path
        if ($Source -match "^https?://") {
            $isUrl = $true
            Write-InstallLog -Message "Source identified as URL" -LogFile $logFile
            
            $fileName = [System.IO.Path]::GetFileName($Source.Split('?')[0])
            if ([string]::IsNullOrWhiteSpace($fileName) -or $fileName -notmatch "\.msi$") {
                $fileName = "installer_$timestamp.msi"
            }
            $localMsiPath = Join-Path -Path $DownloadPath -ChildPath $fileName
            
            # Download the file
            Get-FileFromUrl -Url $Source -DestinationPath $localMsiPath -ExpectedHash $ExpectedHash -LogFile $logFile
            $downloadedFile = $true
            
        } else {
            # Local file
            Write-InstallLog -Message "Source identified as local path" -LogFile $logFile
            $localMsiPath = $Source
            
            if (!(Test-Path -Path $localMsiPath)) {
                throw "Local file not found: $localMsiPath"
            }
            
            if ([System.IO.Path]::GetExtension($localMsiPath) -ne ".msi") {
                Write-InstallLog -Message "Warning: File does not have .msi extension" -Level "WARNING" -LogFile $logFile
            }
        }
        
        # Get file information
        $fileInfo = Get-Item -Path $localMsiPath
        Write-InstallLog -Message "File size: $([math]::Round($fileInfo.Length / 1MB, 2)) MB" -LogFile $logFile
        
        # Check digital signature
        try {
            $signature = Get-AuthenticodeSignature -FilePath $localMsiPath
            Write-InstallLog -Message "Signature status: $($signature.Status)" -LogFile $logFile
            if ($signature.SignerCertificate) {
                Write-InstallLog -Message "Signed by: $($signature.SignerCertificate.Subject)" -LogFile $logFile
            }
        } catch {
            Write-InstallLog -Message "Could not check digital signature: $_" -Level "WARNING" -LogFile $logFile
        }
        
        # Build msiexec arguments
        $msiexecArgs = @("/i", "`"$localMsiPath`"", "/qn")
        
        # Add noreboot flag
        if ($NoReboot) {
            $msiexecArgs += "/norestart"
        }
        
        # Add log file
        if ($MsiLogLevel) {
            $msiexecArgs += "/l$MsiLogLevel"
            $msiexecArgs += "`"$msiLogFile`""
        }
        
        # Add transform file if provided
        if ($TransformFile -and (Test-Path -Path $TransformFile)) {
            Write-InstallLog -Message "Using transform file: $TransformFile" -LogFile $logFile
            $msiexecArgs += "TRANSFORMS=`"$TransformFile`""
        }
        
        # Add properties
        foreach ($key in $Properties.Keys) {
            $value = $Properties[$key]
            $msiexecArgs += "$key=`"$value`""
            Write-InstallLog -Message "Property: $key=$value" -LogFile $logFile
        }
        
        $msiexecArgsString = $msiexecArgs -join " "
        Write-InstallLog -Message "Starting MSI installation..." -LogFile $logFile
        Write-InstallLog -Message "Command: msiexec.exe $msiexecArgsString" -LogFile $logFile
        
        # Start msiexec process
        $processStartInfo = New-Object System.Diagnostics.ProcessStartInfo
        $processStartInfo.FileName = "msiexec.exe"
        $processStartInfo.Arguments = $msiexecArgsString
        $processStartInfo.UseShellExecute = $false
        $processStartInfo.RedirectStandardOutput = $true
        $processStartInfo.RedirectStandardError = $true
        $processStartInfo.CreateNoWindow = $true
        
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $processStartInfo
        
        # Setup output handlers
        $outputBuilder = New-Object System.Text.StringBuilder
        $errorBuilder = New-Object System.Text.StringBuilder
        
        $outputScriptBlock = {
            if ($EventArgs.Data) {
                $Event.MessageData.OutputBuilder.AppendLine($EventArgs.Data) | Out-Null
            }
        }
        
        $errorScriptBlock = {
            if ($EventArgs.Data) {
                $Event.MessageData.ErrorBuilder.AppendLine($EventArgs.Data) | Out-Null
            }
        }
        
        $outputEvent = Register-ObjectEvent -InputObject $process -EventName OutputDataReceived -Action $outputScriptBlock -MessageData @{OutputBuilder = $outputBuilder}
        $errorEvent = Register-ObjectEvent -InputObject $process -EventName ErrorDataReceived -Action $errorScriptBlock -MessageData @{ErrorBuilder = $errorBuilder}
        
        # Start the process
        $process.Start() | Out-Null
        $processId = $process.Id
        Write-InstallLog -Message "Process started with PID: $processId" -LogFile $logFile
        
        $process.BeginOutputReadLine()
        $process.BeginErrorReadLine()
        
        # Wait for process with timeout
        $timeoutMs = $TimeoutMinutes * 60 * 1000
        Write-InstallLog -Message "Waiting for installation to complete (timeout: $TimeoutMinutes minutes)..." -LogFile $logFile
        
        $processExited = $process.WaitForExit($timeoutMs)
        
        if (!$processExited) {
            Write-InstallLog -Message "Installation timed out after $TimeoutMinutes minutes" -Level "ERROR" -LogFile $logFile
            try {
                $process.Kill()
                Write-InstallLog -Message "Process killed due to timeout" -Level "WARNING" -LogFile $logFile
            } catch {
                Write-InstallLog -Message "Could not kill process: $_" -Level "ERROR" -LogFile $logFile
            }
            throw "Installation timed out after $TimeoutMinutes minutes"
        }
        
        # Wait a moment for output capture
        Start-Sleep -Seconds 2
        
        # Get exit code
        $exitCode = $process.ExitCode
        Write-InstallLog -Message "Process exited with code: $exitCode" -LogFile $logFile
        
        # Cleanup event handlers
        Unregister-Event -SourceIdentifier $outputEvent.Name -ErrorAction SilentlyContinue
        Unregister-Event -SourceIdentifier $errorEvent.Name -ErrorAction SilentlyContinue
        $process.Dispose()
        
        # Log captured output
        $stdOutput = $outputBuilder.ToString()
        $stdError = $errorBuilder.ToString()
        
        if ($stdOutput) {
            Write-InstallLog -Message "=== Standard Output ===" -LogFile $logFile
            Write-InstallLog -Message $stdOutput -LogFile $logFile
        }
        
        if ($stdError) {
            Write-InstallLog -Message "=== Standard Error ===" -Level "WARNING" -LogFile $logFile
            Write-InstallLog -Message $stdError -Level "WARNING" -LogFile $logFile
        }
        
        # Parse MSI log file if it exists
        if (Test-Path -Path $msiLogFile) {
            Write-InstallLog -Message "Parsing MSI log file: $msiLogFile" -LogFile $logFile
            try {
                $msiLogContent = Get-Content -Path $msiLogFile -Tail 100 | Where-Object { $_.Trim() -ne "" }
                Write-InstallLog -Message "=== Last 100 lines of MSI log ===" -LogFile $logFile
                foreach ($line in $msiLogContent) {
                    if (![string]::IsNullOrWhiteSpace($line)) {
                        Write-InstallLog -Message $line -LogFile $logFile
                    }
                }
                
                # Look for errors in MSI log
                # Note: Filter out common false positives like "Note: 1: 2205" (table doesn't exist - normal)
                # and "Note: 1: 2228" (query failed - normal when tables don't exist)
                $errorLines = $msiLogContent | Where-Object { 
                    $_ -match "error|failed|return value 3" -and
                    $_ -notmatch "Note: 1: 22(05|28)" -and  # Not table/query errors
                    $_ -notmatch "SELECT.*FROM.*Error" -and  # Not queries of error table
                    $_ -notmatch "Installation success or error status: 0" -and  # Not success message
                    $_ -notmatch "returning 0"  # Not success returns
                }
                if ($errorLines) {
                    Write-InstallLog -Message "=== Potential errors found in MSI log ===" -Level "WARNING" -LogFile $logFile
                    foreach ($errorLine in $errorLines) {
                        if (![string]::IsNullOrWhiteSpace($errorLine)) {
                            Write-InstallLog -Message $errorLine -Level "WARNING" -LogFile $logFile
                        }
                    }
                }
            } catch {
                Write-InstallLog -Message "Could not parse MSI log: $_" -Level "WARNING" -LogFile $logFile
            }
        }
        
        # Check exit code
        if ($ValidExitCodes -contains $exitCode) {
            Write-InstallLog -Message "Installation completed successfully (exit code: $exitCode)" -LogFile $logFile
            if ($exitCode -eq 3010) {
                Write-InstallLog -Message "Note: Reboot required to complete installation" -Level "WARNING" -LogFile $logFile
            } elseif ($exitCode -eq 1641) {
                Write-InstallLog -Message "Note: Installer initiated a reboot" -Level "WARNING" -LogFile $logFile
            }
            $installSuccess = $true
        } else {
            Write-InstallLog -Message "Installation failed with exit code: $exitCode" -Level "ERROR" -LogFile $logFile
            Write-InstallLog -Message "Valid exit codes are: $($ValidExitCodes -join ', ')" -Level "ERROR" -LogFile $logFile
            
            # Common MSI error codes
            $errorMessage = switch ($exitCode) {
                1602 { "User cancelled installation" }
                1603 { "Fatal error during installation" }
                1618 { "Another installation is in progress" }
                1619 { "Installation package could not be opened" }
                1620 { "Installation package could not be opened (verify it's a valid MSI)" }
                1633 { "This installation package is not supported on this platform" }
                1638 { "Another version of this product is already installed" }
                default { "Unknown error code" }
            }
            Write-InstallLog -Message "Error description: $errorMessage" -Level "ERROR" -LogFile $logFile
            
            throw "Installation failed with exit code: $exitCode ($errorMessage)"
        }
        
        # Wait for registry updates
        Write-InstallLog -Message "Waiting 10 seconds for post-install registry updates..." -LogFile $logFile
        Start-Sleep -Seconds 10
        
        # Verify installation if requested
        if ($VerifyInstallation) {
            if ([string]::IsNullOrWhiteSpace($ExpectedAppName)) {
                Write-InstallLog -Message "Cannot verify installation: ExpectedAppName not provided" -Level "WARNING" -LogFile $logFile
            } else {
                Write-InstallLog -Message "Verifying installation of: $ExpectedAppName" -LogFile $logFile
                
                if (Get-Command Get-ApplicationInstallStatus -ErrorAction SilentlyContinue) {
                    $appInstalled = Get-ApplicationInstallStatus -AppName $ExpectedAppName
                    
                    if ($appInstalled) {
                        Write-InstallLog -Message "Verification successful: $ExpectedAppName is installed" -LogFile $logFile
                    } else {
                        Write-InstallLog -Message "Verification failed: $ExpectedAppName not found in Add/Remove Programs" -Level "ERROR" -LogFile $logFile
                        $installSuccess = $false
                        throw "Installation verification failed: Application not found in registry"
                    }
                } else {
                    Write-InstallLog -Message "Get-ApplicationInstallStatus function not available, skipping verification" -Level "WARNING" -LogFile $logFile
                }
            }
        }
        
    } catch {
        Write-InstallLog -Message "Installation failed: $_" -Level "ERROR" -LogFile $logFile
        Write-InstallLog -Message "Stack trace: $($_.ScriptStackTrace)" -Level "ERROR" -LogFile $logFile
        $installSuccess = $false
        throw
    } finally {
        # Cleanup downloaded file if requested
        if ($downloadedFile -and !$KeepDownloadedFile -and (Test-Path -Path $localMsiPath)) {
            try {
                Remove-Item -Path $localMsiPath -Force -ErrorAction Stop
                Write-InstallLog -Message "Cleaned up downloaded file: $localMsiPath" -LogFile $logFile
            } catch {
                Write-InstallLog -Message "Could not delete downloaded file: $_" -Level "WARNING" -LogFile $logFile
            }
        }
        
        Write-InstallLog -Message "========== Installation Ended ==========" -LogFile $logFile
        Write-InstallLog -Message "Installation successful: $installSuccess" -LogFile $logFile
        Write-InstallLog -Message "Script log: $logFile" -LogFile $logFile
        if (Test-Path -Path $msiLogFile) {
            Write-InstallLog -Message "MSI log: $msiLogFile" -LogFile $logFile
        }
        Write-Host "`nInstallation log saved to: $logFile" -ForegroundColor Cyan
        if (Test-Path -Path $msiLogFile) {
            Write-Host "MSI detailed log: $msiLogFile" -ForegroundColor Cyan
        }
    }
    
    # Return result object
    return [PSCustomObject]@{
        Success = $installSuccess
        ExitCode = $exitCode
        LogFile = $logFile
        MsiLogFile = $msiLogFile
        Source = $Source
        LocalPath = $localMsiPath
        AppName = $ExpectedAppName
        Timestamp = $timestamp
    }
}

Function Install-Exe {
    <#
    .SYNOPSIS
    Install EXE files with comprehensive error handling and child process monitoring
    
    .DESCRIPTION
    Robust EXE installation with stub installer detection, child process monitoring,
    exit code handling, and verification. Handles modern stub installers that spawn child processes.
    
    .PARAMETER Source
    URL or local file path to the EXE installer
    
    .PARAMETER Arguments
    Arguments to pass to the installer. Common silent install arguments:
    - InnoSetup: '/VERYSILENT /NORESTART'
    - NSIS: '/S'
    - MSI via EXE: '/quiet /norestart'
    - InstallShield: '/s /v"/qn"'
    
    .PARAMETER ExpectedAppName
    Application name as it appears in Add/Remove Programs for verification
    
    .PARAMETER MonitorChildProcesses
    Monitor child processes spawned by the installer. Default: $true
    
    .PARAMETER ChildProcessNames
    Array of process names to monitor. Default includes common installer names.
    
    .PARAMETER DetectStubInstaller
    Auto-detect stub installers by quick exit time. Default: $true
    
    .PARAMETER ValidExitCodes
    Array of exit codes indicating successful installation. Default: @(0, 3010)
    
    .EXAMPLE
    Install-Exe -Source "app.exe" -Arguments "/VERYSILENT /NORESTART" -ExpectedAppName "MyApp"
    
    .EXAMPLE
    Install-Exe -Source "https://example.com/app.exe" -Arguments "/S" -VerifyInstallation $true
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Source,
        
        [Parameter(Mandatory = $false)]
        [string]$Arguments = "",
        
        [Parameter(Mandatory = $false)]
        [string]$ExpectedAppName,
        
        [Parameter(Mandatory = $false)]
        [string]$DownloadPath = $env:TEMP,
        
        [Parameter(Mandatory = $false)]
        [string]$ExpectedHash,
        
        [Parameter(Mandatory = $false)]
        [int[]]$ValidExitCodes = @(0, 3010),
        
        [Parameter(Mandatory = $false)]
        [int]$TimeoutMinutes = 30,
        
        [Parameter(Mandatory = $false)]
        [boolean]$VerifyInstallation = $false,
        
        [Parameter(Mandatory = $false)]
        [boolean]$KeepDownloadedFile = $false,
        
        [Parameter(Mandatory = $false)]
        [string]$LogPath = "$env:TEMP\InstallLogs",
        
        [Parameter(Mandatory = $false)]
        [boolean]$WaitForProcessExit = $true,
        
        [Parameter(Mandatory = $false)]
        [boolean]$MonitorChildProcesses = $true,
        
        [Parameter(Mandatory = $false)]
        [string[]]$ChildProcessNames = @("msiexec", "setup", "install", "installer", "firefox", "chrome", "winapp", "7z", "un_a"),
        
        [Parameter(Mandatory = $false)]
        [int]$ChildProcessTimeoutMinutes = 30,
        
        [Parameter(Mandatory = $false)]
        [int]$PostInstallWaitSeconds = 10,
        
        [Parameter(Mandatory = $false)]
        [boolean]$DetectStubInstaller = $true
    )
    
    # Initialize variables
    $isUrl = $false
    $localExePath = ""
    $downloadedFile = $false
    $installSuccess = $false
    $logFile = ""
    
    # Create log directory
    if (!(Test-Path -Path $LogPath)) {
        try {
            New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
        } catch {
            Write-Warning "Could not create log directory: $LogPath. Using $env:TEMP"
            $LogPath = $env:TEMP
        }
    }
    
    # Create timestamped log file
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $logFile = Join-Path -Path $LogPath -ChildPath "InstallExe_$timestamp.log"
    
    Write-InstallLog -Message "========== EXE Installation Started ==========" -LogFile $logFile
    Write-InstallLog -Message "Source: $Source" -LogFile $logFile
    Write-InstallLog -Message "Arguments: $Arguments" -LogFile $logFile
    
    try {
        # Determine if source is URL or local path
        if ($Source -match "^https?://") {
            $isUrl = $true
            Write-InstallLog -Message "Source identified as URL" -LogFile $logFile
            
            $fileName = [System.IO.Path]::GetFileName($Source.Split('?')[0])
            if ([string]::IsNullOrWhiteSpace($fileName) -or $fileName -notmatch "\.exe$") {
                $fileName = "installer_$timestamp.exe"
            }
            $localExePath = Join-Path -Path $DownloadPath -ChildPath $fileName
            
            # Download the file
            Get-FileFromUrl -Url $Source -DestinationPath $localExePath -ExpectedHash $ExpectedHash -LogFile $logFile
            $downloadedFile = $true
            
        } else {
            # Local file
            Write-InstallLog -Message "Source identified as local path" -LogFile $logFile
            $localExePath = $Source
            
            if (!(Test-Path -Path $localExePath)) {
                throw "Local file not found: $localExePath"
            }
            
            if ([System.IO.Path]::GetExtension($localExePath) -ne ".exe") {
                Write-InstallLog -Message "Warning: File does not have .exe extension" -Level "WARNING" -LogFile $logFile
            }
        }
        
        # Get file information
        $fileInfo = Get-Item -Path $localExePath
        Write-InstallLog -Message "File size: $([math]::Round($fileInfo.Length / 1MB, 2)) MB" -LogFile $logFile
        Write-InstallLog -Message "File version: $($fileInfo.VersionInfo.FileVersion)" -LogFile $logFile
        Write-InstallLog -Message "Product name: $($fileInfo.VersionInfo.ProductName)" -LogFile $logFile
        
        # Check digital signature
        try {
            $signature = Get-AuthenticodeSignature -FilePath $localExePath
            Write-InstallLog -Message "Signature status: $($signature.Status)" -LogFile $logFile
            if ($signature.SignerCertificate) {
                Write-InstallLog -Message "Signed by: $($signature.SignerCertificate.Subject)" -LogFile $logFile
            }
        } catch {
            Write-InstallLog -Message "Could not check digital signature: $_" -Level "WARNING" -LogFile $logFile
        }
        
        # Prepare process start info
        Write-InstallLog -Message "Starting installation process..." -LogFile $logFile
        Write-InstallLog -Message "Executable: $localExePath" -LogFile $logFile
        Write-InstallLog -Message "Arguments: $Arguments" -LogFile $logFile
        
        $processStartInfo = New-Object System.Diagnostics.ProcessStartInfo
        $processStartInfo.FileName = $localExePath
        $processStartInfo.Arguments = $Arguments
        $processStartInfo.UseShellExecute = $false
        $processStartInfo.RedirectStandardOutput = $true
        $processStartInfo.RedirectStandardError = $true
        $processStartInfo.CreateNoWindow = $true
        
        # Create process
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $processStartInfo
        
        # Setup output handlers
        $outputBuilder = New-Object System.Text.StringBuilder
        $errorBuilder = New-Object System.Text.StringBuilder
        
        $outputScriptBlock = {
            if ($EventArgs.Data) {
                $Event.MessageData.OutputBuilder.AppendLine($EventArgs.Data) | Out-Null
            }
        }
        
        $errorScriptBlock = {
            if ($EventArgs.Data) {
                $Event.MessageData.ErrorBuilder.AppendLine($EventArgs.Data) | Out-Null
            }
        }
        
        $outputEvent = Register-ObjectEvent -InputObject $process -EventName OutputDataReceived -Action $outputScriptBlock -MessageData @{OutputBuilder = $outputBuilder}
        $errorEvent = Register-ObjectEvent -InputObject $process -EventName ErrorDataReceived -Action $errorScriptBlock -MessageData @{ErrorBuilder = $errorBuilder}
        
        # Start the process
        $process.Start() | Out-Null
        $processId = $process.Id
        Write-InstallLog -Message "Process started with PID: $processId" -LogFile $logFile
        
        # Begin async output reading
        $process.BeginOutputReadLine()
        $process.BeginErrorReadLine()
        
        # Wait for process with timeout
        $timeoutMs = $TimeoutMinutes * 60 * 1000
        Write-InstallLog -Message "Waiting for process to complete (timeout: $TimeoutMinutes minutes)..." -LogFile $logFile
        
        $processExited = $process.WaitForExit($timeoutMs)
        
        if (!$processExited) {
            Write-InstallLog -Message "Installation timed out after $TimeoutMinutes minutes" -Level "ERROR" -LogFile $logFile
            try {
                $process.Kill()
                Write-InstallLog -Message "Process killed due to timeout" -Level "WARNING" -LogFile $logFile
            } catch {
                Write-InstallLog -Message "Could not kill process: $_" -Level "ERROR" -LogFile $logFile
            }
            throw "Installation timed out after $TimeoutMinutes minutes"
        }
        
        # Additional wait to ensure all output is captured
        Start-Sleep -Seconds 2
        
        # Get exit code and process runtime
        $exitCode = $process.ExitCode
        $processRuntime = (Get-Date) - $process.StartTime
        Write-InstallLog -Message "Process exited with code: $exitCode" -LogFile $logFile
        Write-InstallLog -Message "Process runtime: $($processRuntime.TotalSeconds) seconds" -LogFile $logFile
        
        # Cleanup event handlers
        Unregister-Event -SourceIdentifier $outputEvent.Name -ErrorAction SilentlyContinue
        Unregister-Event -SourceIdentifier $errorEvent.Name -ErrorAction SilentlyContinue
        $process.Dispose()
        
        # Log captured output
        $stdOutput = $outputBuilder.ToString()
        $stdError = $errorBuilder.ToString()
        
        if ($stdOutput) {
            Write-InstallLog -Message "=== Standard Output ===" -LogFile $logFile
            Write-InstallLog -Message $stdOutput -LogFile $logFile
        }
        
        if ($stdError) {
            Write-InstallLog -Message "=== Standard Error ===" -Level "WARNING" -LogFile $logFile
            Write-InstallLog -Message $stdError -Level "WARNING" -LogFile $logFile
        }
        
        # Detect stub installer
        $isLikelyStubInstaller = $false
        if ($DetectStubInstaller -and $processRuntime.TotalSeconds -lt 10) {
            Write-InstallLog -Message "WARNING: Process exited quickly ($($processRuntime.TotalSeconds) seconds). This may be a stub installer that spawned a child process." -Level "WARNING" -LogFile $logFile
            $isLikelyStubInstaller = $true
        }
        
        # Monitor child processes if enabled or if stub installer detected
        if ($MonitorChildProcesses -or $isLikelyStubInstaller) {
            Write-InstallLog -Message "Monitoring for child processes..." -LogFile $logFile
            Write-InstallLog -Message "Will monitor process names: $($ChildProcessNames -join ', ')" -LogFile $logFile
            Write-InstallLog -Message "Original process PID: $processId" -LogFile $logFile
            
            # Wait a moment for child processes to start
            Start-Sleep -Seconds 3
            
            # Strategy 1: Look for direct children using WMI
            Write-InstallLog -Message "Searching for child processes by parent PID..." -LogFile $logFile
            $childProcesses = @()
            
            try {
                $wmiChildren = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
                    $_.ParentProcessId -eq $processId
                }
                
                if ($wmiChildren) {
                    foreach ($wmiChild in $wmiChildren) {
                        Write-InstallLog -Message "Found child by parent PID: $($wmiChild.Name) (PID: $($wmiChild.ProcessId))" -LogFile $logFile
                        try {
                            $childProc = Get-Process -Id $wmiChild.ProcessId -ErrorAction SilentlyContinue
                            if ($childProc) {
                                $childProcesses += $childProc
                            }
                        } catch {
                            Write-InstallLog -Message "Could not get process object for PID $($wmiChild.ProcessId)" -Level "WARNING" -LogFile $logFile
                        }
                    }
                }
            } catch {
                Write-InstallLog -Message "Could not query WMI for child processes: $_" -Level "WARNING" -LogFile $logFile
            }
            
            # Strategy 2: Look for processes matching common installer names
            Write-InstallLog -Message "Searching for installer processes by name and start time..." -LogFile $logFile
            $allProcesses = Get-Process -ErrorAction SilentlyContinue
            
            foreach ($procName in $ChildProcessNames) {
                $matchingProcs = $allProcesses | Where-Object { 
                    $_.ProcessName -like "*$procName*" -or $_.ProcessName -eq $procName
                }
                if ($matchingProcs) {
                    foreach ($proc in $matchingProcs) {
                        try {
                            $procAge = (Get-Date) - $proc.StartTime
                            if ($procAge.TotalMinutes -lt 2 -and $proc.Id -ne $processId) {
                                if (-not ($childProcesses | Where-Object { $_.Id -eq $proc.Id })) {
                                    $childProcesses += $proc
                                    Write-InstallLog -Message "Found potential child process by name: $($proc.ProcessName) (PID: $($proc.Id), Age: $([math]::Round($procAge.TotalSeconds, 1))s)" -LogFile $logFile
                                }
                            }
                        } catch {
                            # Can't get start time for some processes
                        }
                    }
                }
            }
            
            # Strategy 3: Look for installer-like processes
            Write-InstallLog -Message "Searching for any new processes that started around the same time..." -LogFile $logFile
            $recentProcesses = $allProcesses | Where-Object {
                try {
                    $procAge = (Get-Date) - $_.StartTime
                    $procAge.TotalSeconds -lt 30 -and $_.Id -ne $processId
                } catch {
                    $false
                }
            }
            
            foreach ($proc in $recentProcesses) {
                if ($childProcesses | Where-Object { $_.Id -eq $proc.Id }) {
                    continue
                }
                
                $procName = $proc.ProcessName.ToLower()
                if ($procName -match "setup|install|update|deploy|unpack|extract|helper|stub|bootstrap") {
                    Write-InstallLog -Message "Found installer-like process: $($proc.ProcessName) (PID: $($proc.Id))" -LogFile $logFile
                    $childProcesses += $proc
                }
            }
            
            # Remove duplicates
            $childProcesses = $childProcesses | Select-Object -Unique -Property Id
            
            if ($childProcesses) {
                Write-InstallLog -Message "Monitoring $($childProcesses.Count) child process(es)..." -LogFile $logFile
                $childTimeoutMs = $ChildProcessTimeoutMinutes * 60 * 1000
                
                foreach ($childProc in $childProcesses) {
                    Write-InstallLog -Message "Waiting for: $($childProc.ProcessName) (PID: $($childProc.Id)) - Timeout: $ChildProcessTimeoutMinutes minutes" -LogFile $logFile
                    
                    try {
                        $childProcRefresh = Get-Process -Id $childProc.Id -ErrorAction SilentlyContinue
                        
                        if ($childProcRefresh) {
                            $childExited = $childProcRefresh.WaitForExit($childTimeoutMs)
                            
                            if (!$childExited) {
                                Write-InstallLog -Message "Child process $($childProc.ProcessName) (PID: $($childProc.Id)) did not exit within timeout" -Level "WARNING" -LogFile $logFile
                            } else {
                                Write-InstallLog -Message "Child process $($childProc.ProcessName) (PID: $($childProc.Id)) exited successfully" -LogFile $logFile
                            }
                        } else {
                            Write-InstallLog -Message "Child process $($childProc.ProcessName) (PID: $($childProc.Id)) already exited" -LogFile $logFile
                        }
                    } catch {
                        Write-InstallLog -Message "Error waiting for child process $($childProc.ProcessName): $_" -Level "WARNING" -LogFile $logFile
                    }
                }
                
                Write-InstallLog -Message "Finished monitoring child processes" -LogFile $logFile
            } else {
                if ($isLikelyStubInstaller) {
                    Write-InstallLog -Message "ERROR: Stub installer detected but no child processes found. Installation likely FAILED." -Level "ERROR" -LogFile $logFile
                    $installSuccess = $false
                    throw "Stub installer detected but no child processes found. The installer may have failed silently or requires different arguments."
                } else {
                    Write-InstallLog -Message "No child processes found to monitor" -LogFile $logFile
                }
            }
        }
        
        # Wait for post-install registry updates
        if ($PostInstallWaitSeconds -gt 0) {
            Write-InstallLog -Message "Waiting $PostInstallWaitSeconds seconds for post-install registry updates..." -LogFile $logFile
            Start-Sleep -Seconds $PostInstallWaitSeconds
        }
        
        # Check for common installer log files
        Write-InstallLog -Message "Checking for installer log files..." -LogFile $logFile
        $commonLogPaths = @(
            "$env:TEMP\*.log",
            "$env:LOCALAPPDATA\Temp\*.log",
            "$env:SystemRoot\Temp\*.log"
        )
        
        foreach ($logPattern in $commonLogPaths) {
            try {
                $logFiles = Get-ChildItem -Path $logPattern -ErrorAction SilentlyContinue | 
                    Where-Object { $_.LastWriteTime -gt (Get-Date).AddMinutes(-5) } |
                    Select-Object -First 3
                
                foreach ($installerLog in $logFiles) {
                    Write-InstallLog -Message "Found recent log file: $($installerLog.FullName)" -LogFile $logFile
                    try {
                        $logContent = Get-Content -Path $installerLog.FullName -Tail 30 -ErrorAction Stop | Where-Object { $_.Trim() -ne "" }
                        Write-InstallLog -Message "Last 30 lines of $($installerLog.Name):" -LogFile $logFile
                        foreach ($line in $logContent) {
                            if (![string]::IsNullOrWhiteSpace($line)) {
                                Write-InstallLog -Message $line -LogFile $logFile
                            }
                        }
                    } catch {
                        Write-InstallLog -Message "Could not read log file: $_" -Level "WARNING" -LogFile $logFile
                    }
                }
            } catch {
                # Silently continue
            }
        }
        
        # Check exit code
        if ($ValidExitCodes -contains $exitCode) {
            Write-InstallLog -Message "Installation completed successfully (exit code: $exitCode)" -LogFile $logFile
            $installSuccess = $true
        } else {
            Write-InstallLog -Message "Installation failed with exit code: $exitCode" -Level "ERROR" -LogFile $logFile
            Write-InstallLog -Message "Valid exit codes are: $($ValidExitCodes -join ', ')" -Level "ERROR" -LogFile $logFile
            throw "Installation failed with exit code: $exitCode"
        }
        
        # Verify installation if requested
        if ($VerifyInstallation) {
            if ([string]::IsNullOrWhiteSpace($ExpectedAppName)) {
                Write-InstallLog -Message "Cannot verify installation: ExpectedAppName not provided" -Level "WARNING" -LogFile $logFile
            } else {
                Write-InstallLog -Message "Verifying installation of: $ExpectedAppName" -LogFile $logFile
                
                if (Get-Command Get-ApplicationInstallStatus -ErrorAction SilentlyContinue) {
                    $appInstalled = Get-ApplicationInstallStatus -AppName $ExpectedAppName
                    
                    if ($appInstalled) {
                        Write-InstallLog -Message "Verification successful: $ExpectedAppName is installed" -LogFile $logFile
                    } else {
                        Write-InstallLog -Message "Verification failed: $ExpectedAppName not found in Add/Remove Programs" -Level "ERROR" -LogFile $logFile
                        $installSuccess = $false
                        throw "Installation verification failed: Application not found in registry"
                    }
                } else {
                    Write-InstallLog -Message "Get-ApplicationInstallStatus function not available, skipping verification" -Level "WARNING" -LogFile $logFile
                }
            }
        }
        
    } catch {
        Write-InstallLog -Message "Installation failed: $_" -Level "ERROR" -LogFile $logFile
        Write-InstallLog -Message "Stack trace: $($_.ScriptStackTrace)" -Level "ERROR" -LogFile $logFile
        $installSuccess = $false
        throw
    } finally {
        # Cleanup downloaded file if requested
        if ($downloadedFile -and !$KeepDownloadedFile -and (Test-Path -Path $localExePath)) {
            try {
                Remove-Item -Path $localExePath -Force -ErrorAction Stop
                Write-InstallLog -Message "Cleaned up downloaded file: $localExePath" -LogFile $logFile
            } catch {
                Write-InstallLog -Message "Could not delete downloaded file: $_" -Level "WARNING" -LogFile $logFile
            }
        }
        
        Write-InstallLog -Message "========== Installation Ended ==========" -LogFile $logFile
        Write-InstallLog -Message "Installation successful: $installSuccess" -LogFile $logFile
        Write-InstallLog -Message "Log file location: $logFile" -LogFile $logFile
        Write-Host "`nInstallation log saved to: $logFile" -ForegroundColor Cyan
    }
    
    # Return result object
    return [PSCustomObject]@{
        Success = $installSuccess
        ExitCode = $exitCode
        LogFile = $logFile
        Source = $Source
        LocalPath = $localExePath
        AppName = $ExpectedAppName
        Timestamp = $timestamp
    }
}

Function Get-ApplicationInstallStatus {
    <#
    .SYNOPSIS
    Verify if an application is installed by checking Add/Remove Programs
    
    .DESCRIPTION
    Searches both system (all users) and user install paths to verify an application is installed.
    RMMs typically don't report user-only installed applications, so this helps find those.
    
    .PARAMETER AppName
    Use the name of the application exactly as seen in Add/Remove Programs
    
    .PARAMETER SystemInstallsOnly
    Only check system-wide installations (all users)
    
    .PARAMETER UserInstallsOnly
    Only check user-specific installations
    
    .EXAMPLE
    Get-ApplicationInstallStatus -AppName 'Google Chrome'
    
    .EXAMPLE
    Get-ApplicationInstallStatus -AppName 'Microsoft Teams' -UserInstallsOnly $true
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AppName,
        
        [Parameter(Mandatory = $false)]
        [boolean]$SystemInstallsOnly,
        
        [Parameter(Mandatory = $false)]
        [boolean]$UserInstallsOnly
    )
    
    $installed = @()
    
    if (!$UserInstallsOnly) {
        # Check system locations
        $installed += New-Object psobject -prop @{
            sys32 = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq $AppName }
            sys64 = Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq $AppName }
        }
    }
    
    if (!$SystemInstallsOnly) {
        # Check user install locations
        New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS -ErrorAction SilentlyContinue | Out-Null
        $installed += New-Object psobject -prop @{
            user32 = Get-ItemProperty "HKU:\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq $AppName }
            user64 = Get-ItemProperty "HKU:\*\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq $AppName }
        }
    }
    
    if ($installed.sys32 -or $installed.sys64 -or $installed.user32 -or $installed.user64) {
        return $true
    } else {
        return $false
    }
}

Function Get-InstalledService {
    <#
    .SYNOPSIS
    Verify that services exist and optionally are running
    
    .DESCRIPTION
    Checks if given services exist and optionally verifies they are running.
    Returns $true if all services are present and running (if checked), $false otherwise.
    
    .PARAMETER ServiceNameArray
    Array of service names (not display names) to check
    
    .PARAMETER VerifyServiceRunning
    Also verify services are in running state
    
    .EXAMPLE
    Get-InstalledService -ServiceNameArray 'swprv'
    
    .EXAMPLE
    Get-InstalledService -ServiceNameArray 'swprv','uhssvc' -VerifyServiceRunning $true
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$ServiceNameArray,
        
        [Parameter(Mandatory = $false)]
        [boolean]$VerifyServiceRunning
    )
    
    if (!$VerifyServiceRunning) {
        try {
            Get-Service -Name $ServiceNameArray -ErrorAction Stop | Out-Null
            return $true
        } catch {
            return $false
        }
    } else {
        try {
            Get-Service -Name $ServiceNameArray -ErrorAction Stop | Out-Null
            $ServiceNameArray | ForEach-Object {
                $status = Get-Service -Name $_ | Where-Object { $_.Status -ne 'Running' }
                if ($status) {
                    throw
                }
            }
            return $true
        } catch {
            return $false
        }
    }
}
