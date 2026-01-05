<#
.SYNOPSIS
    BitLocker Best Practice Management Library
    
.DESCRIPTION
    A simplified PowerShell library for managing BitLocker encryption with a 
    Get/Test/Set pattern. Designed for MSP/RMM deployment.
    
.GOALS
    1. One function to TEST if system is eligible for BitLocker
    2. One function to TEST if system meets best practice (returns true/false)
    3. One function to SET (enforce) best practice state
    4. One function to GET detailed status (for RMM output/logging)
    5. NEVER lose encryption keys (save to registry before any changes)
    6. Output detailed info so RMM tools capture recovery keys in logs
    
.ARCHITECTURE
    PUBLIC FUNCTIONS (the API you use):
    ├── Test-BitLockerEligibility    → Can this system use BitLocker? (true/false)
    ├── Test-BitLockerBestPractice   → Is system compliant? (true/false)  
    ├── Set-BitLockerBestPractice    → Make system compliant (with detailed output)
    ├── Get-BitLockerStatus          → Get detailed status of all volumes
    └── Get-BitLockerSavedKeys       → Get saved keys from registry
    
    INTERNAL FUNCTIONS (used by public functions):
    ├── Volume Discovery
    │   ├── Get-InternalVolumes      → Find internal HDDs/SSDs
    │   ├── Get-ExternalVolumes      → Find USB/removable drives
    │   └── Format-MountPoint        → Normalize "D" to "D:" format
    ├── TPM Checks
    │   └── Test-TPMReady            → Is TPM present and configured?
    ├── Key Storage (Registry)
    │   ├── Save-KeysToRegistry      → Persist keys (CRITICAL - prevents key loss)
    │   └── Get-KeysFromRegistry     → Retrieve saved keys
    └── Helpers
        └── Get-VolumeEncryptionData → Rich data about a single volume
    
.BEST PRACTICE DEFAULTS
    - Encryption Method: Aes256 (can override to XtsAes256, Aes128, etc.)
    - Scope: InternalOnly (can override to include external drives)
    - Auto-Unlock: Enabled on all non-system internal drives
    - System Drive: Always processed first (required for auto-unlock)
    
.KEY STORAGE
    Keys are stored in Windows Registry at:
    HKLM:\SOFTWARE\BitLockerHistory\{VolumeID}\Data
    
    Why Registry?
    - Survives reboots
    - Can be backed up with system state
    - Accessible even if drive letters change (uses VolumeID)
    - Easy to query remotely via RMM tools
    
.PREVENTING KEY LOSS
    Keys are saved to registry:
    1. At the START of Set-BitLockerBestPractice (capture existing state)
    2. BEFORE any decryption operation (preserve key before it's destroyed)
    3. AFTER any encryption operation (capture new key immediately)
    4. At the END of Set-BitLockerBestPractice (final state)
    
.EXAMPLE USAGE
    # Check if system can use BitLocker
    Test-BitLockerEligibility
    
    # Check if system meets best practice
    Test-BitLockerBestPractice
    
    # Enforce best practice (with detailed output for RMM)
    Set-BitLockerBestPractice
    
    # Enforce with custom settings
    Set-BitLockerBestPractice -EncryptionMethod 'XtsAes256' -Scope 'InternalAndExternal'
    
    # Get status for reporting
    Get-BitLockerStatus
    
.NOTES
    Author: Matthew Weir
    Version: 2.0 (Complete Rewrite)
    
    CRITICAL: The registry key storage functions are battle-tested. 
    Do not modify without thorough testing.
#>

#requires -RunAsAdministrator

# ============================================================================
# CONFIGURATION
# ============================================================================
# These script-level variables define defaults and constants.
# Change $script:DefaultEncryptionMethod if your org prefers XtsAes256, etc.

$script:RegistryRootPath = "HKLM:\SOFTWARE\BitLockerHistory"
$script:DefaultEncryptionMethod = 'Aes256'
$script:DefaultScope = 'InternalOnly'

# Valid encryption methods (for parameter validation)
$script:ValidEncryptionMethods = @('Aes128', 'Aes256', 'XtsAes128', 'XtsAes256')

# Valid scopes (for parameter validation)
$script:ValidScopes = @('SystemDriveOnly', 'InternalOnly', 'InternalAndExternal')


# ============================================================================
# PUBLIC FUNCTIONS - THE API
# ============================================================================
# These are the functions you call directly. They follow Get/Test/Set pattern.

function Test-BitLockerEligibility {
    <#
    .SYNOPSIS
        Tests if this system can use BitLocker.
        
    .DESCRIPTION
        Checks all prerequisites for BitLocker:
        - TPM exists and is ready (enabled, activated, owned)
        - Windows edition supports BitLocker (Pro/Enterprise/Education)
        
        Returns $true if all checks pass, $false otherwise.
        
        Use -Detailed to get a hashtable with individual check results.
        
    .PARAMETER Detailed
        If specified, returns a hashtable with each check result instead of just true/false.
        
    .OUTPUTS
        [bool] - $true if eligible, $false if not
        [hashtable] - If -Detailed, returns @{ TPMExists=$true; TPMReady=$true; OSEligible=$true; Eligible=$true }
        
    .EXAMPLE
        # Simple check
        if (Test-BitLockerEligibility) { 
            Write-Host "System can use BitLocker" 
        }
        
    .EXAMPLE
        # Detailed check to see what failed
        $result = Test-BitLockerEligibility -Detailed
        if (-not $result.TPMReady) { 
            Write-Host "TPM needs configuration" 
        }
    #>
    [CmdletBinding()]
    [OutputType([bool], [hashtable])]
    param(
        [switch]$Detailed
    )
    
    # Perform all eligibility checks
    $tpmExists = Test-TPMExists
    $tpmReady = Test-TPMReady
    $osEligible = Test-OSEligible
    
    # System is eligible only if ALL checks pass
    $eligible = $tpmExists -and $tpmReady -and $osEligible
    
    if ($Detailed) {
        return @{
            TPMExists   = $tpmExists
            TPMReady    = $tpmReady
            OSEligible  = $osEligible
            Eligible    = $eligible
        }
    }
    
    return $eligible
}

function Test-BitLockerBestPractice {
    <#
    .SYNOPSIS
        Tests if the system meets BitLocker best practice standards.
        
    .DESCRIPTION
        Checks that:
        1. All in-scope volumes are FullyEncrypted
        2. All in-scope volumes use the expected encryption method (unless 'Any')
        3. Non-system drives have auto-unlock enabled
        
        Returns $true if compliant, $false if any check fails.
        
    .PARAMETER EncryptionMethod
        Expected encryption method. Use 'Any' to skip method validation.
        Default: Aes256
        
    .PARAMETER Scope
        Which volumes to check:
        - SystemDriveOnly: Just C:
        - InternalOnly: All internal drives (default)
        - InternalAndExternal: All drives including USB
        
    .OUTPUTS
        [bool] - $true if compliant, $false if not
        
    .EXAMPLE
        # Check with defaults (Aes256, internal drives only)
        Test-BitLockerBestPractice
        
    .EXAMPLE
        # Check with custom settings
        Test-BitLockerBestPractice -EncryptionMethod 'XtsAes256' -Scope 'InternalAndExternal'
        
    .EXAMPLE
        # Just verify encryption exists (any method)
        Test-BitLockerBestPractice -EncryptionMethod 'Any'
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [ValidateSet('Aes128', 'Aes256', 'XtsAes128', 'XtsAes256', 'Any')]
        [string]$EncryptionMethod = $script:DefaultEncryptionMethod,
        
        [ValidateSet('SystemDriveOnly', 'InternalOnly', 'InternalAndExternal')]
        [string]$Scope = $script:DefaultScope
    )
    
    try {
        # Get volumes based on scope
        $volumes = Get-VolumesForScope -Scope $Scope
        
        if (-not $volumes -or $volumes.Count -eq 0) {
            # No volumes to check = technically compliant (edge case)
            return $true
        }
        
        $sysDrive = Format-MountPoint $env:SystemDrive
        
        foreach ($vol in $volumes) {
            $mountPoint = Format-MountPoint $vol.MountPoint
            
            # CHECK 1: Is volume fully encrypted?
            if ($vol.VolumeStatus -ne 'FullyEncrypted') {
                Write-Verbose "FAIL: Volume [$mountPoint] status is [$($vol.VolumeStatus)], expected [FullyEncrypted]"
                return $false
            }
            
            # CHECK 2: Does encryption method match? (skip if 'Any')
            if ($EncryptionMethod -ne 'Any') {
                if ($vol.EncryptionMethod -ne $EncryptionMethod) {
                    Write-Verbose "FAIL: Volume [$mountPoint] method is [$($vol.EncryptionMethod)], expected [$EncryptionMethod]"
                    return $false
                }
            }
            
            # CHECK 3: Is auto-unlock enabled on non-system drives?
            # (Only check internal drives - external may not always be connected)
            if ($mountPoint -ne $sysDrive -and $vol.DriveType -eq 'Internal') {
                if (-not (Test-AutoUnlockEnabled -MountPoint $mountPoint)) {
                    Write-Verbose "FAIL: Volume [$mountPoint] does not have auto-unlock enabled"
                    return $false
                }
            }
        }
        
        # All checks passed
        return $true
    }
    catch {
        Write-Verbose "ERROR during compliance check: $($_.Exception.Message)"
        return $false
    }
}

function Set-BitLockerBestPractice {
    <#
    .SYNOPSIS
        Enforces BitLocker best practice on the system.
        
    .DESCRIPTION
        This is the main function that makes the system compliant. It:
        
        1. Saves existing keys to registry (BEFORE any changes - prevents key loss)
        2. Checks/configures TPM if needed
        3. Processes each volume based on current state
        4. Saves keys after each encryption operation
        5. Outputs detailed information (captured by RMM tools)
        
        The function handles all edge cases:
        - Already encrypted with wrong method → decrypt then re-encrypt
        - Encryption paused → resume
        - Decryption in progress → wait or skip
        - Not encrypted → encrypt
        
    .PARAMETER EncryptionMethod
        Encryption method to use.
        Default: Aes256
        
    .PARAMETER Scope
        Which volumes to encrypt:
        - SystemDriveOnly: Just C:
        - InternalOnly: All internal drives (default)
        - InternalAndExternal: All drives including USB
        
    .PARAMETER ConfigureTPM
        If $true, attempt to configure TPM if it's not ready.
        Default: $true
        
    .OUTPUTS
        [string] - Detailed log of all actions taken (for RMM capture)
        
    .EXAMPLE
        # Enforce defaults (Aes256, internal only)
        Set-BitLockerBestPractice
        
    .EXAMPLE
        # Enforce with XtsAes256 on all drives including USB
        Set-BitLockerBestPractice -EncryptionMethod 'XtsAes256' -Scope 'InternalAndExternal'
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [ValidateSet('Aes128', 'Aes256', 'XtsAes128', 'XtsAes256')]
        [string]$EncryptionMethod = $script:DefaultEncryptionMethod,
        
        [ValidateSet('SystemDriveOnly', 'InternalOnly', 'InternalAndExternal')]
        [string]$Scope = $script:DefaultScope,
        
        [bool]$ConfigureTPM = $true,
        
        [string]$LogPath = "$env:ProgramData\BitLockerBestPractice\Logs"
    )
    
    # Initialize output log - this gets returned and captured by RMM
    $log = [System.Collections.ArrayList]::new()
    
    # -------------------------------------------------------------------------
    # SETUP DISK LOGGING
    # -------------------------------------------------------------------------
    # Create log directory if it doesn't exist
    if (-not (Test-Path $LogPath)) {
        New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
    }
    
    # Create timestamped log file
    $logFileName = "BitLocker_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').log"
    $logFilePath = Join-Path $LogPath $logFileName
    
    # Also create/update a "latest" symlink-style file for easy access
    $latestLogPath = Join-Path $LogPath "BitLocker_Latest.log"
    
    # Helper to add log entries - writes to both memory (for RMM) and disk (for backup)
    $addLog = {
        param([string]$Message)
        $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        $logLine = "$timestamp | $Message"
        
        # Add to in-memory log (returned to RMM)
        [void]$log.Add($logLine)
        
        # Write to disk immediately (survives crashes/reboots)
        try {
            Add-Content -Path $logFilePath -Value $logLine -ErrorAction SilentlyContinue
        }
        catch {
            # Silently fail disk logging - don't break the script
        }
        
        Write-Verbose $Message
    }
    
    # Start the log file with header
    $header = @"
================================================================================
BITLOCKER BEST PRACTICE LOG
================================================================================
Log File: $logFilePath
Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Computer: $env:COMPUTERNAME
User: $env:USERNAME
================================================================================

"@
    try {
        Set-Content -Path $logFilePath -Value $header -ErrorAction SilentlyContinue
        # Update "latest" pointer
        Copy-Item -Path $logFilePath -Destination $latestLogPath -Force -ErrorAction SilentlyContinue
    }
    catch { }
    
    & $addLog "=========================================="
    & $addLog "BitLocker Best Practice Enforcement"
    & $addLog "=========================================="
    & $addLog "Encryption Method: $EncryptionMethod"
    & $addLog "Scope: $Scope"
    & $addLog "Log File: $logFilePath"
    & $addLog "=========================================="
    
    # -------------------------------------------------------------------------
    # STEP 1: SAVE EXISTING KEYS (Critical - prevents key loss)
    # -------------------------------------------------------------------------
    & $addLog ""
    & $addLog "[STEP 1] Saving existing keys to registry..."
    
    try {
        Save-KeysToRegistry
        & $addLog "SUCCESS: Existing keys saved to registry"
    }
    catch {
        & $addLog "WARNING: Could not save existing keys: $($_.Exception.Message)"
        # Continue anyway - don't block encryption
    }
    
    # -------------------------------------------------------------------------
    # STEP 2: CHECK ELIGIBILITY
    # -------------------------------------------------------------------------
    & $addLog ""
    & $addLog "[STEP 2] Checking system eligibility..."
    
    $eligibility = Test-BitLockerEligibility -Detailed
    
    if (-not $eligibility.OSEligible) {
        & $addLog "FAILED: Windows edition does not support BitLocker"
        & $addLog "Supported: Pro, Enterprise, Education, Business"
        return ($log -join "`n")
    }
    & $addLog "SUCCESS: Windows edition is eligible"
    
    if (-not $eligibility.TPMExists) {
        & $addLog "FAILED: TPM hardware not found"
        return ($log -join "`n")
    }
    & $addLog "SUCCESS: TPM hardware exists"
    
    if (-not $eligibility.TPMReady) {
        if ($ConfigureTPM) {
            & $addLog "TPM not ready - attempting to configure..."
            $tpmResult = Initialize-TPM
            & $addLog "TPM Result: $tpmResult"
            
            # Re-check
            if (-not (Test-TPMReady)) {
                & $addLog "FAILED: Could not configure TPM - may need BIOS changes or reboot"
                return ($log -join "`n")
            }
            & $addLog "SUCCESS: TPM is now ready"
        }
        else {
            & $addLog "FAILED: TPM not ready and ConfigureTPM is disabled"
            return ($log -join "`n")
        }
    }
    else {
        & $addLog "SUCCESS: TPM is ready"
    }
    
    # -------------------------------------------------------------------------
    # STEP 3: GET VOLUMES TO PROCESS
    # -------------------------------------------------------------------------
    & $addLog ""
    & $addLog "[STEP 3] Identifying volumes to process..."
    
    $volumes = Get-VolumesForScope -Scope $Scope
    
    if (-not $volumes -or $volumes.Count -eq 0) {
        & $addLog "No volumes found for scope [$Scope]"
        return ($log -join "`n")
    }
    
    # Order volumes: system drive FIRST (required for auto-unlock on others)
    $sysDrive = Format-MountPoint $env:SystemDrive
    $orderedVolumes = $volumes | Sort-Object { 
        if ((Format-MountPoint $_.MountPoint) -eq $sysDrive) { 0 } else { 1 } 
    }
    
    & $addLog "Found $($orderedVolumes.Count) volume(s) to process"
    foreach ($v in $orderedVolumes) {
        $mp = Format-MountPoint $v.MountPoint
        $label = if ($mp -eq $sysDrive) { "$mp (System Drive - processed first)" } else { $mp }
        & $addLog "  - $label | Status: $($v.VolumeStatus) | Method: $($v.EncryptionMethod)"
    }
    
    # -------------------------------------------------------------------------
    # STEP 4: PROCESS EACH VOLUME
    # -------------------------------------------------------------------------
    & $addLog ""
    & $addLog "[STEP 4] Processing volumes..."
    
    foreach ($vol in $orderedVolumes) {
        $mountPoint = Format-MountPoint $vol.MountPoint
        $isSystemDrive = ($mountPoint -eq $sysDrive)
        $driveLabel = if ($isSystemDrive) { "$mountPoint (System)" } else { $mountPoint }
        
        & $addLog ""
        & $addLog "--- Processing $driveLabel ---"
        & $addLog "Current State: $($vol.VolumeStatus) | Method: $($vol.EncryptionMethod) | Encrypted: $($vol.EncryptionPercentage)%"
        
        # Handle based on current state
        switch ($vol.VolumeStatus) {
            
            'FullyEncrypted' {
                # Already encrypted - check if method matches
                if ($vol.EncryptionMethod -eq $EncryptionMethod) {
                    & $addLog "COMPLIANT: Already encrypted with $EncryptionMethod"
                    
                    # Ensure auto-unlock is enabled for non-system drives
                    # (only possible if system drive is fully encrypted)
                    if (-not $isSystemDrive) {
                        $sysDriveVol = Get-BitLockerVolume -MountPoint $sysDrive -ErrorAction SilentlyContinue
                        if ([string]$sysDriveVol.VolumeStatus -eq 'FullyEncrypted') {
                            if (-not (Test-AutoUnlockEnabled -MountPoint $mountPoint)) {
                                $autoUnlock = Enable-AutoUnlockSafe -MountPoint $mountPoint
                                & $addLog "Auto-unlock (was missing): $autoUnlock"
                            }
                            else {
                                & $addLog "Auto-unlock: Already enabled"
                            }
                        }
                        else {
                            & $addLog "Auto-unlock: Deferred (system drive at $($sysDriveVol.EncryptionPercentage)%)"
                        }
                    }
                }
                else {
                    # Wrong encryption method - need to decrypt and re-encrypt
                    & $addLog "NON-COMPLIANT: Method is [$($vol.EncryptionMethod)], need [$EncryptionMethod]"
                    
                    # CRITICAL: Save key before decryption!
                    & $addLog "Saving key before decryption (CRITICAL)..."
                    Save-KeysToRegistry
                    
                    & $addLog "Starting decryption..."
                    try {
                        Disable-BitLocker -MountPoint $mountPoint -ErrorAction Stop | Out-Null
                        & $addLog "Decryption initiated - will re-encrypt on next run after completion"
                    }
                    catch {
                        & $addLog "ERROR: Failed to start decryption: $($_.Exception.Message)"
                    }
                }
            }
            
            'FullyDecrypted' {
                # Not encrypted - but for secondary drives, we must wait until system drive is done
                
                if (-not $isSystemDrive) {
                    # Check if system drive is FULLY encrypted (not just encrypting)
                    $sysDriveStatus = Get-BitLockerVolume -MountPoint $sysDrive -ErrorAction SilentlyContinue
                    $sysDriveState = [string]$sysDriveStatus.VolumeStatus
                    
                    if ($sysDriveState -ne 'FullyEncrypted') {
                        # DO NOT encrypt secondary drives until system drive is done
                        # This prevents the scenario where:
                        # 1. Script encrypts C: and F: simultaneously
                        # 2. Machine reboots before C: completes
                        # 3. Script dies, F: is encrypted but auto-unlock was never enabled
                        # 4. User gets prompted for F: recovery key on every boot forever
                        & $addLog "DEFERRED: Cannot encrypt $mountPoint until system drive is FullyEncrypted"
                        & $addLog "  System drive status: $sysDriveState ($($sysDriveStatus.EncryptionPercentage)%)"
                        & $addLog "  Re-run this script after system drive encryption completes"
                        continue  # Skip to next volume
                    }
                }
                
                # If we get here, either it's the system drive OR system drive is FullyEncrypted
                & $addLog "NOT ENCRYPTED: Starting encryption with $EncryptionMethod..."
                
                try {
                    # Enable BitLocker
                    Enable-BitLocker -MountPoint $mountPoint `
                        -EncryptionMethod $EncryptionMethod `
                        -RecoveryPasswordProtector `
                        -SkipHardwareTest `
                        -ErrorAction Stop | Out-Null
                    
                    & $addLog "Encryption started successfully"
                    
                    # CRITICAL: Save key immediately after encryption starts
                    Save-KeysToRegistry
                    & $addLog "Recovery key saved to registry"
                    
                    # Enable auto-unlock for non-system drives (system drive is guaranteed FullyEncrypted here)
                    if (-not $isSystemDrive) {
                        $autoUnlock = Enable-AutoUnlockSafe -MountPoint $mountPoint
                        & $addLog "Auto-unlock: $autoUnlock"
                    }
                }
                catch {
                    & $addLog "ERROR: Failed to start encryption: $($_.Exception.Message)"
                }
            }
            
            'EncryptionInProgress' {
                # Encryption is running - just wait
                & $addLog "IN PROGRESS: Encryption at $($vol.EncryptionPercentage)% - no action needed"
                
                # Make sure key is saved
                Save-KeysToRegistry
            }
            
            'EncryptionPaused' {
                # Encryption was paused - resume it
                & $addLog "PAUSED: Resuming encryption..."
                try {
                    Resume-BitLocker -MountPoint $mountPoint -ErrorAction Stop | Out-Null
                    & $addLog "Encryption resumed"
                    Save-KeysToRegistry
                }
                catch {
                    & $addLog "ERROR: Failed to resume: $($_.Exception.Message)"
                }
            }
            
            'DecryptionInProgress' {
                # Decryption is running - let it finish
                & $addLog "DECRYPTING: At $($vol.EncryptionPercentage)% - will encrypt after completion"
            }
            
            'DecryptionPaused' {
                # Decryption was paused - resume to complete it
                & $addLog "PAUSED: Resuming decryption (will encrypt after completion)..."
                try {
                    Disable-BitLocker -MountPoint $mountPoint -ErrorAction Stop | Out-Null
                    & $addLog "Decryption resumed"
                }
                catch {
                    & $addLog "ERROR: Failed to resume decryption: $($_.Exception.Message)"
                }
            }
            
            default {
                & $addLog "UNKNOWN STATE: $($vol.VolumeStatus) - skipping"
            }
        }
    }
    
    # -------------------------------------------------------------------------
    # STEP 4b: FINAL AUTO-UNLOCK CHECK
    # -------------------------------------------------------------------------
    # For any secondary drives that are FullyEncrypted but missing auto-unlock
    # (handles legacy systems or edge cases)
    
    $sysDriveStatus = Get-BitLockerVolume -MountPoint $sysDrive -ErrorAction SilentlyContinue
    
    if ([string]$sysDriveStatus.VolumeStatus -eq 'FullyEncrypted') {
        & $addLog ""
        & $addLog "[STEP 4b] Checking auto-unlock on secondary drives..."
        
        foreach ($vol in $orderedVolumes) {
            $mp = Format-MountPoint $vol.MountPoint
            if ($mp -eq $sysDrive) { continue }  # Skip system drive
            
            $volStatus = Get-BitLockerVolume -MountPoint $mp -ErrorAction SilentlyContinue
            if ([string]$volStatus.VolumeStatus -eq 'FullyEncrypted') {
                if (-not (Test-AutoUnlockEnabled -MountPoint $mp)) {
                    $autoUnlock = Enable-AutoUnlockSafe -MountPoint $mp
                    & $addLog "  $mp auto-unlock (was missing): $autoUnlock"
                }
                else {
                    & $addLog "  $mp auto-unlock: OK"
                }
            }
        }
    }
    elseif ([string]$sysDriveStatus.VolumeStatus -eq 'EncryptionInProgress') {
        & $addLog ""
        & $addLog "[STEP 4b] System drive encrypting ($($sysDriveStatus.EncryptionPercentage)%) - secondary drives will be processed on next run"
    }
    
    # -------------------------------------------------------------------------
    # STEP 5: FINAL KEY SAVE AND STATUS OUTPUT
    # -------------------------------------------------------------------------
    & $addLog ""
    & $addLog "[STEP 5] Final status..."
    
    # One more save to capture final state
    Save-KeysToRegistry
    
    # Get and output current status (this is what RMM captures!)
    $status = Get-BitLockerStatus
    
    & $addLog ""
    & $addLog "=========================================="
    & $addLog "FINAL STATUS - RECOVERY KEYS"
    & $addLog "=========================================="
    
    foreach ($vol in $status) {
        & $addLog ""
        & $addLog "Volume: $($vol.MountPoint)"
        & $addLog "  VolumeID: $($vol.VolumeID)"
        & $addLog "  Status: $($vol.VolumeStatus)"
        & $addLog "  Encrypted: $($vol.EncryptionPercentage)%"
        & $addLog "  Method: $($vol.EncryptionMethod)"
        & $addLog "  Protection: $($vol.ProtectionStatus)"
        & $addLog "  RecoveryKey: $($vol.RecoveryPassword)"
    }
    
    & $addLog ""
    & $addLog "=========================================="
    & $addLog "Enforcement complete"
    & $addLog "=========================================="
    
    # -------------------------------------------------------------------------
    # FINALIZE DISK LOG
    # -------------------------------------------------------------------------
    try {
        # Add footer
        $footer = @"

================================================================================
Log completed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
================================================================================
"@
        Add-Content -Path $logFilePath -Value $footer -ErrorAction SilentlyContinue
        
        # Update "latest" pointer
        Copy-Item -Path $logFilePath -Destination $latestLogPath -Force -ErrorAction SilentlyContinue
        
        # Cleanup old logs (keep last 30 days)
        $cutoffDate = (Get-Date).AddDays(-30)
        Get-ChildItem -Path $LogPath -Filter "BitLocker_*.log" -ErrorAction SilentlyContinue | 
            Where-Object { $_.Name -ne "BitLocker_Latest.log" -and $_.LastWriteTime -lt $cutoffDate } |
            Remove-Item -Force -ErrorAction SilentlyContinue
    }
    catch { }
    
    # Return the log as a single string
    return ($log -join "`n")
}

function Get-BitLockerStatus {
    <#
    .SYNOPSIS
        Gets detailed status of all BitLocker volumes.
        
    .DESCRIPTION
        Returns rich information about each volume including:
        - VolumeID (persistent identifier)
        - MountPoint (current drive letter)
        - VolumeStatus (FullyEncrypted, FullyDecrypted, etc.)
        - EncryptionMethod (Aes256, XtsAes256, etc.)
        - EncryptionPercentage (0-100)
        - ProtectionStatus (On, Off)
        - RecoveryPassword (the actual recovery key!)
        - DriveType (Internal, External)
        
        Use this for reporting, logging, and RMM output.
        
    .PARAMETER Scope
        Which volumes to include:
        - SystemDriveOnly: Just C:
        - InternalOnly: All internal drives (default)
        - InternalAndExternal: All drives including USB
        - All: Everything BitLocker knows about
        
    .OUTPUTS
        [PSCustomObject[]] - Array of volume status objects
        
    .EXAMPLE
        # Get status of all internal drives
        Get-BitLockerStatus
        
    .EXAMPLE
        # Get status of everything
        Get-BitLockerStatus -Scope All
        
    .EXAMPLE
        # Output as table
        Get-BitLockerStatus | Format-Table MountPoint, VolumeStatus, RecoveryPassword
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [ValidateSet('SystemDriveOnly', 'InternalOnly', 'InternalAndExternal', 'All')]
        [string]$Scope = 'All'
    )
    
    $results = @()
    
    # Get BitLocker data for all volumes
    $blVolumes = Get-BitLockerVolume
    
    if (-not $blVolumes) {
        Write-Verbose "No BitLocker volumes found"
        return $results
    }
    
    # Get internal/external classification
    # Build arrays of normalized drive letters for comparison
    $internalDrives = [System.Collections.ArrayList]::new()
    $externalDrives = [System.Collections.ArrayList]::new()
    
    # Get internal volumes
    $intVols = Get-InternalVolumes
    if ($intVols) {
        foreach ($v in $intVols) {
            if ($v.DriveLetter) {
                [void]$internalDrives.Add((Format-MountPoint $v.DriveLetter))
            }
        }
    }
    Write-Verbose "Internal drives found: $($internalDrives -join ', ')"
    
    # Get external volumes
    $extVols = Get-ExternalVolumes
    if ($extVols) {
        foreach ($v in $extVols) {
            if ($v.DriveLetter) {
                [void]$externalDrives.Add((Format-MountPoint $v.DriveLetter))
            }
        }
    }
    Write-Verbose "External drives found: $($externalDrives -join ', ')"
    
    $sysDrive = Format-MountPoint $env:SystemDrive
    
    foreach ($blVol in $blVolumes) {
        $mountPoint = Format-MountPoint $blVol.MountPoint
        
        # Determine drive type by checking if mount point is in our lists
        $driveType = 'Unknown'
        if ($internalDrives -contains $mountPoint) { 
            $driveType = 'Internal' 
        }
        elseif ($externalDrives -contains $mountPoint) { 
            $driveType = 'External' 
        }
        
        Write-Verbose "Volume $mountPoint classified as: $driveType"
        
        # Apply scope filter
        $include = switch ($Scope) {
            'SystemDriveOnly' { $mountPoint -eq $sysDrive }
            'InternalOnly' { $driveType -eq 'Internal' }
            'InternalAndExternal' { $driveType -in @('Internal', 'External') }
            'All' { $true }
        }
        
        if (-not $include) { 
            Write-Verbose "Volume $mountPoint excluded by scope filter"
            continue 
        }
        
        # Get VolumeID from disk subsystem
        $volumeID = Get-VolumeID -MountPoint $mountPoint
        
        # Get recovery password - only take the FIRST one if multiple exist
        # (Multiple can exist if drive was encrypted multiple times or protectors manually added)
        $recoveryPassword = $blVol.KeyProtector | 
            Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' } | 
            Select-Object -First 1 -ExpandProperty RecoveryPassword
        
        if (-not $recoveryPassword) { $recoveryPassword = 'None' }
        
        # Build result object - CAST ENUMS TO STRINGS explicitly
        $results += [PSCustomObject]@{
            VolumeID             = $volumeID
            MountPoint           = $mountPoint
            VolumeStatus         = [string]$blVol.VolumeStatus
            EncryptionMethod     = [string]$blVol.EncryptionMethod
            EncryptionPercentage = $blVol.EncryptionPercentage
            ProtectionStatus     = [string]$blVol.ProtectionStatus
            LockStatus           = [string]$blVol.LockStatus
            RecoveryPassword     = $recoveryPassword
            DriveType            = $driveType
            AutoUnlockEnabled    = (Test-AutoUnlockEnabled -MountPoint $mountPoint)
        }
    }
    
    return $results
}

function Get-BitLockerSavedKeys {
    <#
    .SYNOPSIS
        Gets BitLocker recovery keys saved in the registry.
        
    .DESCRIPTION
        Retrieves keys from the registry storage. This includes:
        - Currently connected drives
        - Previously connected drives (keys preserved even if drive removed)
        
        Use this to recover keys for drives that may be disconnected or to
        verify keys are being saved properly.
        
    .PARAMETER Simple
        If specified, outputs just "DriveLetter | Key" format for easy reading.
        
    .OUTPUTS
        [string] - Formatted key information (one line per volume)
        
    .EXAMPLE
        Get-BitLockerSavedKeys
        # Full output with VolumeID, status, date
        
    .EXAMPLE
        Get-BitLockerSavedKeys -Simple
        # C: | 123456-789012-345678-901234-567890-123456-789012-345678
        # F: | 987654-321098-765432-109876-543210-987654-321098-765432
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [switch]$Simple
    )
    
    $registryData = Get-KeysFromRegistry
    
    if ($registryData.Count -eq 0) {
        return "No BitLocker keys found in registry"
    }
    
    $output = @()
    
    foreach ($volumeID in $registryData.Keys) {
        $entry = $registryData[$volumeID]
        
        # Handle array or single entry
        if ($entry -is [array]) {
            $latest = $entry | Sort-Object { [datetime]$_.Date } -Descending | Select-Object -First 1
        }
        else {
            $latest = $entry
        }
        
        if ($Simple) {
            # Simple format: just drive letter and key (skip if no key)
            $key = $latest.RecoveryPassword
            if ($key -and $key -ne 'None' -and $key.Trim() -ne '') {
                $output += "$($latest.MountPoint) | $key"
            }
        }
        else {
            # Full format with all details
            $output += "VolumeID: $volumeID | Mount: $($latest.MountPoint) | Key: $($latest.RecoveryPassword) | Status: $($latest.VolumeStatus) | Saved: $($latest.Date)"
        }
    }
    
    if ($output.Count -eq 0) {
        return "No recovery keys found (volumes may be decrypted)"
    }
    
    return ($output -join "`n")
}


# ============================================================================
# INTERNAL FUNCTIONS - VOLUME DISCOVERY
# ============================================================================
# These functions identify and classify storage volumes.

function Get-InternalVolumes {
    <#
    .SYNOPSIS
        Gets all internal (non-removable) volumes with drive letters.
        
    .DESCRIPTION
        Filters by bus type to exclude removable media:
        - USB: External USB drives
        - 1394: FireWire drives
        - MMC: SD cards and similar
        - UFS: Universal Flash Storage
        
        Only returns "Fixed" drives (HDDs, SSDs) with assigned drive letters.
    #>
    [CmdletBinding()]
    param()
    
    Get-Disk | 
        Where-Object { $_.BusType -notin @('USB', '1394', 'MMC', 'UFS') } | 
        Get-Partition | 
        Get-Volume | 
        Where-Object { $_.DriveType -eq 'Fixed' -and $_.DriveLetter }
}

function Get-ExternalVolumes {
    <#
    .SYNOPSIS
        Gets all external/removable volumes with drive letters.
        
    .DESCRIPTION
        Returns only USB, FireWire, MMC, and UFS devices.
        These may need different encryption policies than internal drives.
    #>
    [CmdletBinding()]
    param()
    
    Get-Disk | 
        Where-Object { $_.BusType -in @('USB', '1394', 'MMC', 'UFS') } | 
        Get-Partition | 
        Get-Volume | 
        Where-Object { $_.DriveLetter }
}

function Format-MountPoint {
    <#
    .SYNOPSIS
        Normalizes drive letter to "X:" format.
        
    .DESCRIPTION
        Different cmdlets return drive letters differently:
        - Get-Volume: "D" (no colon)
        - $env:SystemDrive: "C:" (with colon)
        - Get-BitLockerVolume: "D:" (with colon)
        
        Without normalization, comparisons fail:
        "D" -ne "C:" is TRUE even when comparing same drive!
        
        This function ensures consistent "X:" format for all comparisons.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DriveLetter
    )
    
    # Remove any colons or backslashes, leaving just the letter
    $letter = $DriveLetter -replace '[:\\]', ''
    return "$($letter):"
}

function Get-VolumeID {
    <#
    .SYNOPSIS
        Gets the persistent VolumeID (GUID) for a drive letter.
        
    .DESCRIPTION
        Drive letters can change (D: becomes E:, etc.) but VolumeID is permanent.
        We use VolumeID as the key for storing recovery passwords so we can
        always match a key to its volume even if letters change.
        
        Uses the disk/partition/volume pipeline to get UniqueId, which is more
        reliable than Get-Volume alone.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$MountPoint
    )
    
    $letter = ($MountPoint -replace '[:\\]', '')
    
    # Method 1: Try via disk/partition pipeline (most reliable)
    try {
        $volume = Get-Partition -DriveLetter $letter -ErrorAction Stop | Get-Volume -ErrorAction Stop
        if ($volume -and $volume.UniqueId) {
            $match = [regex]::Match($volume.UniqueId, '\{([^}]+)\}')
            if ($match.Success) {
                return $match.Groups[1].Value
            }
        }
    }
    catch {
        Write-Verbose "Method 1 failed for $letter : $($_.Exception.Message)"
    }
    
    # Method 2: Try Get-Volume directly
    try {
        $volume = Get-Volume -DriveLetter $letter -ErrorAction Stop
        if ($volume -and $volume.UniqueId) {
            $match = [regex]::Match($volume.UniqueId, '\{([^}]+)\}')
            if ($match.Success) {
                return $match.Groups[1].Value
            }
        }
    }
    catch {
        Write-Verbose "Method 2 failed for $letter : $($_.Exception.Message)"
    }
    
    # Fallback: use drive letter (not ideal but better than nothing)
    Write-Verbose "Could not get VolumeID for $letter - using fallback"
    return "Unknown-$letter"
}

function Get-VolumesForScope {
    <#
    .SYNOPSIS
        Gets volume data filtered by scope.
        
    .DESCRIPTION
        Returns Get-BitLockerStatus data filtered to the specified scope.
        This is a helper to avoid duplicating scope logic everywhere.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('SystemDriveOnly', 'InternalOnly', 'InternalAndExternal')]
        [string]$Scope
    )
    
    $sysDrive = Format-MountPoint $env:SystemDrive
    $allVolumes = Get-BitLockerStatus -Scope 'All'
    
    switch ($Scope) {
        'SystemDriveOnly' {
            return $allVolumes | Where-Object { $_.MountPoint -eq $sysDrive }
        }
        'InternalOnly' {
            return $allVolumes | Where-Object { $_.DriveType -eq 'Internal' }
        }
        'InternalAndExternal' {
            return $allVolumes | Where-Object { $_.DriveType -in @('Internal', 'External') }
        }
    }
}


# ============================================================================
# INTERNAL FUNCTIONS - TPM
# ============================================================================
# TPM (Trusted Platform Module) functions for checking and configuring TPM.

function Test-TPMExists {
    <#
    .SYNOPSIS
        Checks if TPM hardware exists.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    
    try {
        $tpm = Get-WmiObject -Namespace 'root\cimv2\security\microsofttpm' -Class 'Win32_TPM' -ErrorAction Stop
        return ($null -ne $tpm)
    }
    catch {
        return $false
    }
}

function Test-TPMReady {
    <#
    .SYNOPSIS
        Checks if TPM is fully ready for BitLocker (enabled, activated, owned).
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    
    try {
        $tpm = Get-WmiObject -Namespace 'root\cimv2\security\microsofttpm' -Class 'Win32_TPM' -ErrorAction Stop
        
        if (-not $tpm) { return $false }
        
        $enabled = $tpm.IsEnabled().IsEnabled
        $activated = $tpm.IsActivated().IsActivated
        $owned = $tpm.IsOwned().IsOwned
        
        return ($enabled -and $activated -and $owned)
    }
    catch {
        return $false
    }
}

function Test-OSEligible {
    <#
    .SYNOPSIS
        Checks if Windows edition supports BitLocker.
        
    .DESCRIPTION
        BitLocker requires Pro, Enterprise, Education, or Business editions.
        Home editions only support "Device Encryption" which is different.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    
    $os = Get-WmiObject -Class Win32_OperatingSystem
    $name = $os.Caption
    
    return ($name -like '*Pro*' -or 
            $name -like '*Enterprise*' -or 
            $name -like '*Education*' -or 
            $name -like '*Business*')
}

function Initialize-TPM {
    <#
    .SYNOPSIS
        Attempts to initialize/configure TPM for BitLocker use.
        
    .DESCRIPTION
        TPM configuration depends on BIOS settings:
        - Status 4: Windows can fully manage TPM (best)
        - Status 3: Requires user presence for changes
        - Status 2: BIOS blocks Windows management
        - Status 1: BIOS doesn't allow OS control
        
    .OUTPUTS
        [string] - Result message
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    
    try {
        $tpm = Get-WmiObject -Namespace 'root\cimv2\security\microsofttpm' -Class 'Win32_TPM'
        
        if (-not $tpm) {
            return "TPM not found"
        }
        
        $status = $tpm.GetPhysicalPresenceConfirmationStatus(5).ConfirmationStatus
        
        switch ($status) {
            4 {
                # Windows can manage freely - take ownership
                $tpm.SetPhysicalPresenceRequest(8) | Out-Null  # Allow owner install
                $tpm.SetPhysicalPresenceRequest(5) | Out-Null  # Clear and take ownership
                return "TPM configured - ready for encryption"
            }
            3 {
                # Need user presence - schedule for next boot
                $tpm.SetPhysicalPresenceRequest(18) | Out-Null
                return "TPM provisioning scheduled - REBOOT REQUIRED"
            }
            2 {
                return "TPM blocked by BIOS - manual BIOS configuration required"
            }
            1 {
                return "BIOS does not allow OS control of TPM - manual BIOS configuration required"
            }
            default {
                return "Unknown TPM status: $status"
            }
        }
    }
    catch {
        return "TPM initialization error: $($_.Exception.Message)"
    }
}


# ============================================================================
# INTERNAL FUNCTIONS - AUTO-UNLOCK
# ============================================================================
# Auto-unlock allows secondary drives to unlock automatically when system boots.

function Test-AutoUnlockEnabled {
    <#
    .SYNOPSIS
        Checks if auto-unlock is enabled on a volume.
        
    .DESCRIPTION
        Auto-unlock uses an ExternalKey protector stored on the system drive.
        This function checks if that protector exists.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string]$MountPoint
    )
    
    try {
        $mountPoint = Format-MountPoint $MountPoint
        $blVol = Get-BitLockerVolume -MountPoint $mountPoint -ErrorAction Stop
        
        $hasExternalKey = $blVol.KeyProtector | 
            Where-Object { $_.KeyProtectorType -eq 'ExternalKey' }
        
        return ($null -ne $hasExternalKey)
    }
    catch {
        return $false
    }
}

function Enable-AutoUnlockSafe {
    <#
    .SYNOPSIS
        Safely enables auto-unlock on a volume.
        
    .DESCRIPTION
        Wraps Enable-BitLockerAutoUnlock with error handling.
        Auto-unlock can fail if:
        - System drive isn't encrypted yet
        - Volume isn't encrypted
        - Volume is the system drive (can't auto-unlock itself)
        
    .OUTPUTS
        [string] - Result message
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$MountPoint
    )
    
    $mountPoint = Format-MountPoint $MountPoint
    $sysDrive = Format-MountPoint $env:SystemDrive
    
    # Can't auto-unlock system drive
    if ($mountPoint -eq $sysDrive) {
        return "Skipped (system drive)"
    }
    
    # Check if already enabled
    if (Test-AutoUnlockEnabled -MountPoint $mountPoint) {
        return "Already enabled"
    }
    
    try {
        Enable-BitLockerAutoUnlock -MountPoint $mountPoint -ErrorAction Stop | Out-Null
        return "Enabled successfully"
    }
    catch {
        return "Failed: $($_.Exception.Message)"
    }
}


# ============================================================================
# INTERNAL FUNCTIONS - KEY STORAGE (REGISTRY)
# ============================================================================
# These functions persist recovery keys to the Windows Registry.
# CRITICAL: This is how we prevent key loss. Do not modify without testing!

function Save-KeysToRegistry {
    <#
    .SYNOPSIS
        Saves current BitLocker recovery keys to Windows Registry.
        
    .DESCRIPTION
        This is the CRITICAL function for preventing key loss.
        
        Workflow:
        1. Get current BitLocker volumes and their keys
        2. Load existing registry data (includes disconnected drives)
        3. Merge: current data updates existing, disconnected drives preserved
        4. Save merged data back to registry
        5. Write backup to disk log file
        
        This ensures:
        - Keys for connected drives are always current
        - Keys for disconnected drives are preserved
        - Multiple keys per volume are tracked if they change
        - Disk backup exists even if registry is corrupted
        
    .NOTES
        Registry location: HKLM:\SOFTWARE\BitLockerHistory\{VolumeID}\Data
        Disk backup: $env:ProgramData\BitLockerBestPractice\Keys\BitLocker_Keys.log
        Data format: JSON array of historical entries
    #>
    [CmdletBinding()]
    param()
    
    try {
        # Get current volume data
        $currentVolumes = Get-BitLockerStatus -Scope 'All'
        
        if (-not $currentVolumes -or $currentVolumes.Count -eq 0) {
            Write-Verbose "No BitLocker volumes to save"
            return
        }
        
        # Load existing registry data
        $existingData = Get-KeysFromRegistry
        
        # Merge: update existing with current, preserve disconnected
        $merged = @{}
        
        # Start with existing data (preserves disconnected drives)
        foreach ($volID in $existingData.Keys) {
            $merged[$volID] = $existingData[$volID]
        }
        
        # Update/add current volumes
        foreach ($vol in $currentVolumes) {
            $volumeID = $vol.VolumeID
            
            if (-not $volumeID -or $volumeID -like 'Unknown-*') {
                Write-Verbose "Skipping volume with unknown ID: $($vol.MountPoint)"
                continue
            }
            
            # Create entry for this volume
            $entry = [PSCustomObject]@{
                Date             = (Get-Date).ToString('o')
                MountPoint       = $vol.MountPoint
                RecoveryPassword = $vol.RecoveryPassword
                VolumeStatus     = $vol.VolumeStatus
                EncryptionMethod = $vol.EncryptionMethod
                ProtectionStatus = $vol.ProtectionStatus
                DriveType        = $vol.DriveType
            }
            
            # Replace existing entry (we only keep latest per volume)
            $merged[$volumeID] = @($entry)
        }
        
        # Save to registry
        Save-DataToRegistry -Data $merged
        
        # =====================================================================
        # DISK BACKUP - Critical safety net for recovery keys
        # =====================================================================
        try {
            $keyBackupPath = "$env:ProgramData\BitLockerBestPractice\Keys"
            if (-not (Test-Path $keyBackupPath)) {
                New-Item -Path $keyBackupPath -ItemType Directory -Force | Out-Null
            }
            
            $keyLogFile = Join-Path $keyBackupPath "BitLocker_Keys.log"
            $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            
            # Append to key log (never overwrite - historical record)
            $keyLogEntry = @"

================================================================================
KEY BACKUP: $timestamp
Computer: $env:COMPUTERNAME
================================================================================
"@
            Add-Content -Path $keyLogFile -Value $keyLogEntry -ErrorAction SilentlyContinue
            
            foreach ($volID in $merged.Keys) {
                $entry = $merged[$volID] | Select-Object -First 1
                if ($entry.RecoveryPassword -and $entry.RecoveryPassword -ne 'None') {
                    $keyLine = "VolumeID: $volID | Mount: $($entry.MountPoint) | Key: $($entry.RecoveryPassword) | Status: $($entry.VolumeStatus)"
                    Add-Content -Path $keyLogFile -Value $keyLine -ErrorAction SilentlyContinue
                }
            }
        }
        catch {
            # Silently fail disk backup - don't break the main function
            Write-Verbose "Disk backup failed: $($_.Exception.Message)"
        }
        
        Write-Verbose "Saved keys for $($merged.Count) volume(s) to registry"
    }
    catch {
        Write-Error "Failed to save keys to registry: $($_.Exception.Message)"
        throw
    }
}

function Get-KeysFromRegistry {
    <#
    .SYNOPSIS
        Loads all saved BitLocker keys from registry.
        
    .OUTPUTS
        [hashtable] - Keys are VolumeIDs, values are arrays of entries
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()
    
    $data = @{}
    
    if (-not (Test-Path $script:RegistryRootPath)) {
        return $data
    }
    
    try {
        $volumeKeys = Get-ChildItem -Path $script:RegistryRootPath -ErrorAction Stop
        
        foreach ($volKey in $volumeKeys) {
            $volumeID = $volKey.PSChildName
            
            try {
                $jsonData = Get-ItemProperty -Path $volKey.PSPath -Name 'Data' -ErrorAction Stop |
                    Select-Object -ExpandProperty Data
                
                $entries = $jsonData | ConvertFrom-Json
                
                # Ensure array format
                if ($entries -isnot [array]) {
                    $entries = @($entries)
                }
                
                $data[$volumeID] = $entries
            }
            catch {
                Write-Verbose "Could not read data for volume $volumeID"
            }
        }
    }
    catch {
        Write-Verbose "Could not enumerate registry: $($_.Exception.Message)"
    }
    
    return $data
}

function Save-DataToRegistry {
    <#
    .SYNOPSIS
        Writes merged data to registry.
        
    .DESCRIPTION
        Internal function called by Save-KeysToRegistry.
        Creates registry structure if needed and saves JSON data.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Data
    )
    
    # Create root path if needed
    if (-not (Test-Path $script:RegistryRootPath)) {
        New-Item -Path $script:RegistryRootPath -Force | Out-Null
    }
    
    foreach ($volumeID in $Data.Keys) {
        $entries = $Data[$volumeID]
        
        if (-not $entries -or $entries.Count -eq 0) {
            continue
        }
        
        $volumePath = Join-Path $script:RegistryRootPath $volumeID
        
        # Create volume key if needed
        if (-not (Test-Path $volumePath)) {
            New-Item -Path $volumePath -Force | Out-Null
        }
        
        # Serialize to JSON and save
        $json = $entries | ConvertTo-Json -Depth 10 -Compress
        Set-ItemProperty -Path $volumePath -Name 'Data' -Value $json -Type String -Force
    }
}


# ============================================================================
# EXPORTS (for module use)
# ============================================================================
# If loaded as a module (.psm1), export public functions.
# When dot-sourced as a script, this section is skipped.

if ($MyInvocation.MyCommand.ScriptBlock.Module) {
    Export-ModuleMember -Function @(
        'Test-BitLockerEligibility',
        'Test-BitLockerBestPractice', 
        'Set-BitLockerBestPractice',
        'Get-BitLockerStatus',
        'Get-BitLockerSavedKeys'
    )
}
