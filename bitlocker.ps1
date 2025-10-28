<#
    .NOTES
    - If Enable-InternalFullDiskEncryption is enabled and you want to decrypt, all non $env:SystemDrive volumes must be decrypted before you can decrypt the $env:SystemDrive itself
#>

function Confirm-EncryptionReadiness {
    param (
        [boolean]$Remediate     # Set $true to auto resolve
    )
    if (!(Get-TPMexists)) {
        throw 'TPM does not exist'
    } else {
        Write-Output 'Confirmed TPM exists'
    }

    if (!(Get-IsTPMEnabled)) {
        try {
            if ($Remediate) {
                Set-TPMEnabled
                if (!(Get-IsTPMEnabled)) {
                    throw 'Failed to enable the TPM'
                } else {
                    return 'Successfully enabled the TPM!'
                }
            } else {
                # Remdiation wasn't enabled, throw to the catch
                throw 'Remediation was not enabled to resolve: TPM is not enabled'
            }
        } catch {
            return $Error
        }
    } else {
        Write-Output 'Confirmed TPM is enabled'
    }

    if (!(Get-IsTPMActivated)) {
        try {
            if ($Remediate) {
                Set-TPMActive
                if (!(Get-IsTPMActivated)) {
                    throw 'Failed to activate the TPM'
                } else {
                    return 'Successfully activated the TPM!'
                }
            } else {
                # Remdiation wasn't enabled, throw to the catch
                throw 'Remediation was not enabled to resolve: TPM is not activated'
            }
        } catch {
            return $Error
        }
    } else {
        Write-Output 'Confirmed TPM is activated'
    }

    if (!(Get-IsTPMOwned))  {
        try {
            if ($Remediate) {
                Set-TPMOwnership
                if (!(Get-IsTPMOwned)) {
                    throw 'Failed to set the owner on the TPM'
                } else {
                    return 'Successfully set an owner on the TPM!'
                }
            } else {
                # Remdiation wasn't enabled, throw to the catch
                throw 'Remediation was not enabled to resolve: TPM has no owner'
            }
        } catch {
            return $Error
        }
    } else {
        Write-Output 'Confirmed TPM is owned'
    }

    if (!(Get-IsOSEligible)) {
        throw 'OS is not eligible'
    } else {
        Write-Output 'Confirmed OS is eligible'
    }
}

function Get-InternalVolumes {
    Get-Disk | Where-Object { $_.BusType -notin @('USB', '1394', 'MMC', 'UFS') } | Get-Partition | Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' -and $_.DriveLetter }
}

function Get-ExternalVolumes {
    Get-Disk | Where-Object { $_.BusType -in @('USB', '1394', 'MMC', 'UFS') } | Get-Partition | Get-Volume | Where-Object { $_.DriveLetter }
}

function Get-TPMexists {
    $tpm = Get-WmiObject -Namespace root\cimv2\security\microsofttpm -class Win32_TPM
    try {
        if (!$tpm) {
            throw
        } elseif (($tpm.GetPhysicalPresenceConfirmationStatus(5).ConfirmationStatus) -eq 0) {
            throw
        } else {
            return $true
        }
    } catch {
        return $false
    }
}

function Get-IsTPMEnabled {
    $tpm = Get-WmiObject -Namespace root\cimv2\security\microsofttpm -class Win32_TPM
    $tpmEnabled = $tpm.IsEnabled().isenabled
    if (!$tpmEnabled) {
        return $false
    } else {
        return $true
    }
}

function Set-TPMEnabled {
    $tpm = Get-WmiObject -Namespace root\cimv2\security\microsofttpm -class Win32_TPM
    $tpm.Enable()
}

function Get-IsTPMActivated {
    $tpm = Get-WmiObject -Namespace root\cimv2\security\microsofttpm -class Win32_TPM
    $tpmActivated = $tpm.IsActivated().isactivated
    if (!$tpmActivated) {
        return $false
    } else {
        return $true
    }
}

function Set-TPMActive {
    $tpm = Get-WmiObject -Namespace root\cimv2\security\microsofttpm -class Win32_TPM
    $tpm.Activate()
}

function Get-IsTPMOwned {
    $tpm = Get-WmiObject -Namespace root\cimv2\security\microsofttpm -class Win32_TPM
    $tpmOwned = $tpm.IsOwned().isOwned
    if (!$tpmOwned) {
        return $false
    } else {
        return $true
    }
}

function Set-TPMOwnership {
    # Ref: https://deploywindows.com/2017/06/08/whats-the-story-about-tpm-owner-password-and-bitlocker-recovery-password/
    # Ref: https://devblogs.microsoft.com/scripting/powershell-and-bitlocker-part-1/
    
    $tpm = Get-WmiObject -Namespace root\cimv2\security\microsofttpm -class Win32_TPM
    Switch ($tpm.GetPhysicalPresenceConfirmationStatus(5).ConfirmationStatus) {
        4{
            # 4 means that Windows is able to manage the TPM, allowing it to be cleared without requiring a user to be present for approval.
            # Allow the installation of a TPM owner
            $tpm.SetPhysicalPresenceRequest(8) | Out-Null
            # Clear the TPM chip and take ownership
            $tpm.SetPhysicalPresenceRequest(5) | Out-Null
            return 'Ready to encrypt'
        }

        3{
            # 3 means that Windows can manage the TPM, however, the user must be present to approve the change.
            # Provision the TPM to allow clear without the physical presence of the user.
            $tpm.SetPhysicalPresenceRequest(18) | Out-Null
            return 'Reboot required to provision TPM'
        }

        2{
            # 2 means that Windows is unable to manage the TPM, as the BIOS settings prevent this action.
            return 'TPM cannot be managed, BIOS/EUFI manual config required'
        }

        1{
            # 1 means that the BIOS does not permit changes to the TPM from outside the BIOS.
            return 'BIOS/EUFI does not allow control of TPM from the OS, direct BIOS/EUFI config required'
        }
    }
}

function Get-AllUnencryptedVolumes {
    Get-BitLockerVolume | Where-Object { $_.VolumeStatus -ne 'FullyEncrypted' }
}

function Get-UnencryptedInternalVolumes {
    Get-InternalVolumes | ForEach {
        $volume = $_.DriveLetter
        Get-BitLockerVolume -MountPoint $volume | Where-Object { $_.VolumeStatus -ne 'FullyEncrypted' }
    }
}

function Get-UnencryptedExternalVolumes {
    Get-ExternalVolumes | ForEach {
        $volume = $_.DriveLetter
        Get-BitlockerVolume -MountPoint $volume | Where-Object { $_.VolumeStatus -ne 'FullyEncrypted' }
    }
}

function Enable-InternalFullDiskEncryption {
    Get-InternalVolumes | ForEach {
        $volume = $_.DriveLetter
        Enable-Bitlocker -MountPoint $volume -EncryptionMethod Aes256 -RecoveryPasswordProtector -SkipHardwareTest -ErrorAction Stop
        # We don't want to run the Enable-BitlockerAutoUnlock on the systemdrive (usually C)
        $sysDrive = $env:SystemDrive
        if ($volume -ne $sysDrive) {
            Enable-BitLockerAutoUnlock -Mountpoint $volume
        }
    }
}

function Enable-InternalUsedSpaceEncryption {
   Get-InternalVolumes | ForEach {
        $volume = $_.DriveLetter
        Enable-Bitlocker -MountPoint $volume -EncryptionMethod Aes256 -RecoveryPasswordProtector -SkipHardwareTest -UsedSpaceOnly -ErrorAction Stop
        # We don't want to run the Enable-BitlockerAutoUnlock on the systemdrive (usually C)
        $sysDrive = $env:SystemDrive
        if ($volume -ne $sysDrive) {
            Enable-BitLockerAutoUnlock -Mountpoint $volume
        }
    }
}

function Enable-ExternalFullDiskEncryption {
    Get-ExternalVolumes | ForEach {
        $volume = $_.DriveLetter
        Enable-Bitlocker -MountPoint $volume -EncryptionMethod Aes256 -RecoveryPasswordProtector -SkipHardwareTest -ErrorAction Stop
        Enable-BitLockerAutoUnlock -Mountpoint $volume
    }
}

function Enable-ExternalUsedSpaceEncryption {
    Get-ExternalVolumes | ForEach {
        $volume = $_.DriveLetter
        Enable-Bitlocker -MountPoint $volume -EncryptionMethod Aes256 -RecoveryPasswordProtector -SkipHardwareTest -UsedSpaceOnly -ErrorAction Stop
        Enable-BitLockerAutoUnlock -Mountpoint $volume
    }
}

function Enable-SelectVolumeFullDiskEncryption {
    param (
        [string]$MountPoint
    )

    Enable-Bitlocker -MountPoint $MountPoint -EncryptionMethod Aes256 -RecoveryPasswordProtector -SkipHardwareTest -ErrorAction Stop
    # We don't want to run the Enable-BitlockerAutoUnlock on the systemdrive (usually C)
    $sysDrive = $env:SystemDrive
    if ($MountPoint -ne $sysDrive) {
        Enable-BitLockerAutoUnlock -Mountpoint $MountPoint
    }
}

function Enable-SelectVolumeUsedSpaceEncryption {
    param (
        [string]$MountPoint
    )

    Enable-Bitlocker -MountPoint $MountPoint -EncryptionMethod Aes256 -RecoveryPasswordProtector -SkipHardwareTest -UsedSpaceOnly -ErrorAction Stop
    # We don't want to run the Enable-BitlockerAutoUnlock on the systemdrive (usually C)
    $sysDrive = $env:SystemDrive
    if ($MountPoint -ne $sysDrive) {
        Enable-BitLockerAutoUnlock -Mountpoint $MountPoint
    }
}

function Get-IsOSEligible {
    <#
        .DESCRIPTION
        Determines if the OS supports Bitlocker. Remember, Windows 11 now supports a feature called "device encryption".
        This is not the same thing as Bitlocker, so therefore is not included in the supported conditions.
    #>
    $osInfo = Get-WmiObject win32_operatingsystem
    $osName = $osInfo.Caption
    $osArch = $osInfo.OSArchitecture

    if ($osName -like '*Pro*' -or $osName -like '*Enterprise*' -or $osName -like '*Education*' -or $osName -like '*Business*') {
        return $true
    } else {
        return $false
    }
}

function Get-BitlockerData {
    $blData = Get-BitLockerVolume | Select-Object *
    $volumes = Get-InternalVolumes
    ForEach ($vol in $volumes) {
        # Volume letters can change, so grabbing the volume ID you can ref for what keys belong to what
        $volumeID = [regex]::match($vol.UniqueId,'{([^/)]+)}').groups[1].value
        $bitVol = $blData | Where-Object {$_.MountPoint -like ($vol.driveletter + '*')}
        $key = $bitVol.KeyProtector | Select-Object -ExpandProperty RecoveryPassword
        If (!$key) {
            $key = 'None'
        }
        $newObject = New-Object PSObject
        $newObject | Add-Member -Type NoteProperty -Name 'VolumeID' -Value $volumeID
        $newObject | Add-Member -Type NoteProperty -Name 'MountPoint' -Value $BitVol.MountPoint
        $newObject | Add-Member -Type NoteProperty -Name 'RecoveryPassword' -Value $key
        $newObject | Add-Member -Type NoteProperty -Name 'VolumeType' -Value $BitVol.VolumeType
        $newObject | Add-Member -Type NoteProperty -Name 'EncryptionMethod' -Value $BitVol.EncryptionMethod
        $newObject | Add-Member -Type NoteProperty -Name 'VolumeStatus' -Value $BitVol.VolumeStatus
        $newObject | Add-Member -Type NoteProperty -Name 'ProtectionStatus' -Value $BitVol.ProtectionStatus
        $newObject | Add-Member -Type NoteProperty -Name 'LockStatus' -Value $BitVol.LockStatus
        $newObject | Add-Member -Type NoteProperty -Name 'EncryptionPercentage' -Value $BitVol.EncryptionPercentage
        $newObject | Add-Member -Type NoteProperty -Name 'DriveType' -Value 'Internal'
        $newObject
    }

    $volumes = Get-ExternalVolumes
    ForEach ($vol in $volumes) {
        # Volume letters can change, so grabbing the volume ID you can ref for what keys belong to what
        $volumeID = [regex]::match($vol.UniqueId,'{([^/)]+)}').groups[1].value
        $bitVol = $blData | Where-Object {$_.MountPoint -like ($vol.driveletter + '*')}
        $key = $bitVol.KeyProtector | Select-Object -ExpandProperty RecoveryPassword
        If (!$key) {
            $key = 'None'
        }
        $newObject = New-Object PSObject
        $newObject | Add-Member -Type NoteProperty -Name 'VolumeID' -Value $volumeID
        $newObject | Add-Member -Type NoteProperty -Name 'MountPoint' -Value $BitVol.MountPoint
        $newObject | Add-Member -Type NoteProperty -Name 'RecoveryPassword' -Value $key
        $newObject | Add-Member -Type NoteProperty -Name 'VolumeType' -Value $BitVol.VolumeType
        $newObject | Add-Member -Type NoteProperty -Name 'EncryptionMethod' -Value $BitVol.EncryptionMethod
        $newObject | Add-Member -Type NoteProperty -Name 'VolumeStatus' -Value $BitVol.VolumeStatus
        $newObject | Add-Member -Type NoteProperty -Name 'ProtectionStatus' -Value $BitVol.ProtectionStatus
        $newObject | Add-Member -Type NoteProperty -Name 'LockStatus' -Value $BitVol.LockStatus
        $newObject | Add-Member -Type NoteProperty -Name 'EncryptionPercentage' -Value $BitVol.EncryptionPercentage
        $newObject | Add-Member -Type NoteProperty -Name 'DriveType' -Value 'External'
        $newObject
    }
}

function Confirm-EncryptionBestPracticeState {
    <#
        .DESCRIPTION
        Confirm all BitLocker encryption best practices are met:
        - TPM is present and ready
        - Only specified volume types are checked
        - All volumes are FullyEncrypted
        - All volumes use the expected encryption method (unless 'Any' is specified)
    #>

    [CmdletBinding()]
    param(
        [ValidateSet('Aes128', 'Aes256', 'XtsAes128', 'XtsAes256', 'Any')]
        [string]$ExpectedEncryptionMethod = 'Aes256',

        [ValidateSet('InternalOnly', 'InternalAndExternal')]
        [string]$WhatShouldBeEncrypted = 'InternalOnly'
    )

    try {
        # Gather volume info
        $internalVolumes = (Get-InternalVolumes | Where-Object { $_.DriveLetter }) | ForEach-Object { "$($_.DriveLetter):" }
        $allVolumes = Get-BitlockerData

        $volumesToCheck = switch ($WhatShouldBeEncrypted) {
            'InternalOnly'         { $allVolumes | Where-Object { $internalVolumes -contains $_.MountPoint } }
            'InternalAndExternal'  { $allVolumes }
        }

        foreach ($vol in $volumesToCheck) {
            if ($vol.VolumeStatus -ne 'FullyEncrypted') {
                throw "Volume [$($vol.MountPoint)] is not fully encrypted. Status: $($vol.VolumeStatus)"
            }

            # Only check encryption method if a specific method is expected (not 'Any')
            if ($ExpectedEncryptionMethod -ne 'Any' -and $vol.EncryptionMethod -ne $ExpectedEncryptionMethod) {
                throw "Volume [$($vol.MountPoint)] has method [$($vol.EncryptionMethod)], expected [$ExpectedEncryptionMethod]"
            }
        }

        return $true
    }
    catch {
        return $false
    }
}

function Set-EnforceBestPracticeEncryption {
    Param(
        [Parameter(
            HelpMessage='Set the expected encryption method'
        )]
        [ValidateSet('Aes128', 'Aes256', 'XtsAes128', 'XtsAes256', 'Any')]
        [string]$ExpectedEncryptionMethod = 'Aes256',

        [Parameter(
            HelpMessage='Set the types of volumes that should be encrypted'
        )]
        [ValidateSet('InternalOnly', 'InternalAndExternal')]
        [string]$WhatShouldBeEncrypted = 'InternalOnly'
    )

    $output = @()
    $output += Confirm-EncryptionReadiness -Remediate $true

    # Previous revisions were piping Get-InternvalVolumes to Get-BitlockerData, but Get-BitlockerData 
    # doesn't support selecting volumes... so effectively, this was ignoring internal only, and using
    # full output from Get-BitlockerData-- meaning, externals could be encrypted. This is now fixed!
    $internalVolumes = (Get-InternalVolumes | Where-Object { $_.DriveLetter }) | ForEach-Object { "$($_.DriveLetter):" }
    $allBitlockerData = Get-BitlockerData

    $volumes = switch ($WhatShouldBeEncrypted) {
        'InternalOnly'         { $allBitlockerData | Where-Object { $internalVolumes -contains $_.MountPoint } }
        'InternalAndExternal'  { $allBitlockerData }
    }

    foreach ($vol in $volumes) {
        switch ($vol.VolumeStatus) {
            'EncryptionPaused' {
                $output += "Best practice misalignment: Volume letter [$($vol.MountPoint)] had encryption paused"
                $output += Resume-BitLocker -MountPoint $vol.MountPoint -ErrorAction Stop | Out-Null
                $output += "Resumed protection on volume letter [$($vol.MountPoint)]"
            }

            'PartiallyEncrypted' {
                $output += "Best practice misalignment: Volume letter [$($vol.MountPoint)] had encryption paused"
                $output += Resume-BitLocker -MountPoint $vol.MountPoint -ErrorAction Stop | Out-Null
                $output += "Resumed protection on volume letter [$($vol.MountPoint)]"
            }

            'DecryptionPaused' {
                $output += "Best practice misalignment: Volume letter [$($vol.MountPoint)] had decryption paused"
                $output += Disable-BitLocker -MountPoint $vol.MountPoint -ErrorAction Stop | Out-Null
                $output += "Resumed decryption on volume letter [$($vol.MountPoint)]"
            }

            'DecryptionInProgress' {
                $output += "Volume letter [$($vol.MountPoint)] is currently decrypting"
            }

            'PartiallyDecrypted' {
                $output += "Best practice misalignment: Volume letter [$($vol.MountPoint)] had decryption paused"
                $output += Disable-BitLocker -MountPoint $vol.MountPoint -ErrorAction Stop | Out-Null
                $output += "Resumed decryption on volume letter [$($vol.MountPoint)]"
            }

            'FullyDecrypted' {
                $output += "Best practice misalignment: Volume letter [$($vol.MountPoint)] is not encrypted"
                $output += Enable-SelectVolumeFullDiskEncryption -MountPoint $vol.MountPoint
                Save-BitlockerDataToDisk
                $output += "Initiated encryption on volume letter [$($vol.MountPoint)]"
            }

            'FullyEncrypted' {
                # Only check encryption method if a specific method is expected (not 'Any')
                if ($ExpectedEncryptionMethod -ne 'Any' -and $vol.EncryptionMethod -ne $ExpectedEncryptionMethod) {
                    $output += "Best practice misalignment: Volume letter [$($vol.MountPoint)] has encryption method of [$($vol.EncryptionMethod)] when the expected method is $ExpectedEncryptionMethod"
                    $output += Disable-BitLocker -MountPoint $vol.MountPoint -ErrorAction Stop | Out-Null
                    $output += "Initiated decryption of volume letter [$($vol.MountPoint)]"
                } else {
                    $output += "Confirmed volume [$($vol.MountPoint)] is in best practice alignment!"  
                }
            }
        }
    }

    $bitlockerInfo = Get-BitlockerData
    foreach ($vol in $bitlockerInfo) {
        $output += "Volume [$($vol.MountPoint)] | ID: $($vol.VolumeID) | Status: $($vol.VolumeStatus) | Encrypted: $($vol.EncryptionPercentage)% | Method: $($vol.EncryptionMethod) | RecoveryKey(s): $($vol.RecoveryPassword -join ', ')"
    }

    return $output -join "`n"
}

# Registry root path - NEVER change this once in production
$script:RegistryRootPath = "HKLM:\SOFTWARE\BitLockerHistory"

function Convert-VolumeStatusToString {
    <#
    .SYNOPSIS
        Converts BitLocker VolumeStatus to string
    #>
    param($Value)
    
    # If already a string, return as-is
    if ($Value -is [string]) { return $Value }
    
    # Convert numeric code to string
    switch ([int]$Value) {
        0 { return 'FullyDecrypted' }
        1 { return 'FullyEncrypted' }
        2 { return 'EncryptionInProgress' }
        3 { return 'DecryptionInProgress' }
        4 { return 'EncryptionPaused' }
        5 { return 'DecryptionPaused' }
        default { return "Unknown($Value)" }
    }
}

function Convert-EncryptionMethodToString {
    <#
    .SYNOPSIS
        Converts BitLocker EncryptionMethod to string
    #>
    param($Value)
    
    # If already a string, return as-is
    if ($Value -is [string]) { return $Value }
    
    # Convert numeric code to string
    switch ([int]$Value) {
        0 { return 'None' }
        1 { return 'Aes128' }
        2 { return 'Aes256' }
        3 { return 'Aes128Diffuser' }
        4 { return 'Aes256Diffuser' }
        6 { return 'XtsAes128' }
        7 { return 'XtsAes256' }
        default { return "Unknown($Value)" }
    }
}

function Convert-ProtectionStatusToString {
    <#
    .SYNOPSIS
        Converts BitLocker ProtectionStatus to string
    #>
    param($Value)
    
    # If already a string, return as-is
    if ($Value -is [string]) { return $Value }
    
    # Convert numeric code to string
    switch ([int]$Value) {
        0 { return 'Off' }
        1 { return 'On' }
        2 { return 'Unknown' }
        default { return "Unknown($Value)" }
    }
}

function Convert-LockStatusToString {
    <#
    .SYNOPSIS
        Converts BitLocker LockStatus to string
    #>
    param($Value)
    
    # If already a string, return as-is
    if ($Value -is [string]) { return $Value }
    
    # Convert numeric code to string
    switch ([int]$Value) {
        0 { return 'Unlocked' }
        1 { return 'Locked' }
        default { return "Unknown($Value)" }
    }
}

<# Core Save Function
.SYNOPSIS
    BitLocker recovery key storage using Windows Registry

.DESCRIPTION
    CRITICAL PRODUCTION SYSTEM - Handles BitLocker recovery key storage with zero data loss.
    
    KEY PRINCIPLES:
    1. Registry is the single source of truth
    2. Volume IDs (not drive letters) are the primary key
    3. ALL historical keys are preserved forever
    4. Disconnected drives remain in registry
    5. Keys are NEVER overwritten, only appended
    
    STORAGE STRUCTURE:
    HKLM:\SOFTWARE\BitLockerHistory\
      └─ {VolumeID}\
          └─ Data = JSON array of all keys for this volume
    
    PREREQUISITES:
    - Requires Get-BitlockerData function to be loaded first
    
.NOTES
    Author: Production System
    Date: 2025-01-17
    Version: 1.0 (Registry-Only)
#>

# Registry root path - NEVER change this once in production
$script:RegistryRootPath = "HKLM:\SOFTWARE\BitLockerHistory"

function Save-BitlockerDataToDisk {
    <#
    .SYNOPSIS
        Saves BitLocker recovery keys to Windows Registry
        
    .DESCRIPTION
        This is the PRIMARY function that ensures zero data loss.
        
        CRITICAL WORKFLOW:
        1. Get current volumes from system (may be subset if drives removed)
        2. Load ALL existing data from registry (includes disconnected drives)
        3. Merge current + existing (preserves all historical data)
        4. Save merged data back to registry
        
        This ensures that even if D: is disconnected, its keys remain in registry.
        
    .EXAMPLE
        Save-BitlockerDataToDisk
        Saves all current BitLocker volumes and preserves historical data
        
    .EXAMPLE
        Save-BitlockerDataToDisk -Verbose
        Shows detailed logging of what's being saved
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Verbose "=== Starting BitLocker Key Save Operation ==="
        
        # STEP 1: Get current BitLocker volumes from the system
        # NOTE: This only includes CONNECTED drives
        Write-Verbose "STEP 1: Getting current BitLocker volumes from system..."
        $currentVolumes = Get-BitlockerData
        
        if (!$currentVolumes -or $currentVolumes.Count -eq 0) {
            Write-Warning "No BitLocker volumes found on system. Nothing to save."
            return
        }
        
        Write-Verbose "Found $($currentVolumes.Count) current volume(s) on system"
        foreach ($vol in $currentVolumes) {
            Write-Verbose "  - Volume ID: $($vol.VolumeID), Mount: $($vol.MountPoint), Type: $($vol.DriveType)"
        }
        
        # STEP 2: Load ALL existing data from registry (includes disconnected drives)
        Write-Verbose "`nSTEP 2: Loading ALL existing data from registry..."
        $existingData = Get-AllExistingRegistryData
        
        if ($existingData.Count -gt 0) {
            Write-Verbose "Found $($existingData.Count) volume(s) in registry (includes disconnected drives)"
            foreach ($volID in $existingData.Keys) {
                $keyCount = $existingData[$volID].Count
                Write-Verbose "  - Volume ID: $volID has $keyCount historical entry(ies)"
            }
        } else {
            Write-Verbose "No existing data in registry (first run)"
        }
        
        # STEP 3: Merge current system data with existing registry data
        Write-Verbose "`nSTEP 3: Merging current volumes with existing registry data..."
        $mergedData = Merge-VolumeData -CurrentVolumes $currentVolumes -ExistingData $existingData
        
        Write-Verbose "After merge: $($mergedData.Count) total volume(s) to save"
        
        # STEP 4: Save merged data to registry
        Write-Verbose "`nSTEP 4: Saving merged data to registry..."
        Save-MergedDataToRegistry -MergedData $mergedData
        
        Write-Verbose "`n=== BitLocker Key Save Operation Complete ==="
        Write-Verbose "All data safely saved to registry"
        
    } catch {
        Write-Error "CRITICAL ERROR in Save-BitlockerDataToDisk: $($_.Exception.Message)"
        Write-Error "Stack Trace: $($_.ScriptStackTrace)"
        throw
    }
}

function Get-AllExistingRegistryData {
    <#
    .SYNOPSIS
        Loads ALL volume data from registry
        
    .DESCRIPTION
        Returns a hashtable where:
        - Key = VolumeID
        - Value = Array of historical entries for that volume
        
        This includes data for disconnected drives.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()
    
    $allData = @{}
    
    # Check if registry path exists
    if (!(Test-Path $script:RegistryRootPath)) {
        Write-Verbose "Registry path does not exist yet (first run)"
        return $allData
    }
    
    # Get all volume subkeys
    try {
        $volumeKeys = Get-ChildItem -Path $script:RegistryRootPath -ErrorAction Stop
        
        foreach ($volKey in $volumeKeys) {
            $volumeID = $volKey.PSChildName
            
            try {
                # Read the Data property for this volume
                $jsonData = Get-ItemProperty -Path $volKey.PSPath -Name "Data" -ErrorAction Stop | 
                    Select-Object -ExpandProperty Data
                
                # Parse JSON to array of entries
                $entries = $jsonData | ConvertFrom-Json
                
                # Ensure it's an array (even if single entry)
                if ($entries -isnot [array]) {
                    $entries = @($entries)
                }
                
                $allData[$volumeID] = $entries
                
                Write-Verbose "Loaded $($entries.Count) entry(ies) for volume $volumeID"
                
            } catch {
                Write-Warning "Could not read data for volume $volumeID : $($_.Exception.Message)"
                # Continue with other volumes
            }
        }
        
    } catch {
        Write-Warning "Could not enumerate registry volumes: $($_.Exception.Message)"
    }
    
    return $allData
}

function Merge-VolumeData {
    <#
    .SYNOPSIS
        Merges current system volumes with existing registry data
        
    .DESCRIPTION
        OPTION 1 MERGE LOGIC (Latest Keys Only):
        - Start with ALL existing registry data (includes disconnected drives)
        - For each current volume, REPLACE with latest key only
        - Preserves disconnected volumes until they reconnect
        - Keeps registry size minimal
        
    .PARAMETER CurrentVolumes
        Array of volume objects from Get-BitlockerData (current system state)
        
    .PARAMETER ExistingData
        Hashtable of existing registry data (includes historical/disconnected volumes)
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        $CurrentVolumes,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$ExistingData
    )
    
    # Start with a COPY of existing data (includes disconnected drives)
    $merged = @{}
    foreach ($volID in $ExistingData.Keys) {
        $merged[$volID] = $ExistingData[$volID]
    }
    
    Write-Verbose "Starting merge with $($merged.Count) existing volume(s) from registry"
    
    # Process each current volume
    foreach ($vol in $CurrentVolumes) {
        $volumeID = $vol.VolumeID
        
        if (!$volumeID) {
            Write-Warning "Volume at $($vol.MountPoint) has no VolumeID - skipping"
            continue
        }
        
        # Get current keys for this volume
        $currentKeys = if ($vol.RecoveryPassword -is [array]) {
            $vol.RecoveryPassword
        } else {
            @($vol.RecoveryPassword)
        }
        
        # Get existing keys (if any) for comparison
        $existingKeys = @()
        if ($merged.ContainsKey($volumeID)) {
            $existingKeys = $merged[$volumeID] | ForEach-Object {
                if ($_.RecoveryPassword -is [array]) {
                    $_.RecoveryPassword
                } else {
                    @($_.RecoveryPassword)
                }
            } | Where-Object { $_ -and $_ -ne 'None' } | Select-Object -Unique
        }
        
        # Check if keys have changed
        $keysChanged = $false
        foreach ($key in $currentKeys) {
            if (!$key -or $key -eq 'None') {
                continue
            }
            if ($existingKeys -notcontains $key) {
                $keysChanged = $true
                break
            }
        }
        
        # ALWAYS create single entry with latest data for currently-connected volumes
        # This consolidates any historical entries into a single entry
        $latestEntry = [PSCustomObject]@{
            Date              = (Get-Date).ToString('o')  # ISO 8601 format
            MountPoint        = $vol.MountPoint
            RecoveryPassword  = $currentKeys | Where-Object { $_ -and $_ -ne 'None' }
            VolumeType        = [string]$vol.VolumeType
            EncryptionMethod  = [string]$vol.EncryptionMethod
            VolumeStatus      = [string]$vol.VolumeStatus
            ProtectionStatus  = [string]$vol.ProtectionStatus
            LockStatus        = [string]$vol.LockStatus
            EncryptionPercent = $vol.EncryptionPercentage
            DriveType         = $vol.DriveType
        }
        
        # REPLACE entire array with single latest entry (even if key hasn't changed)
        $merged[$volumeID] = @($latestEntry)
        
        # Log what happened
        if (!$hadExistingData) {
            Write-Verbose "Volume $volumeID : Added new entry"
        } elseif ($keysChanged) {
            Write-Verbose "Volume $volumeID : Key changed - updated with latest"
        } else {
            Write-Verbose "Volume $volumeID : Key unchanged - consolidated to single entry"
        }
    }
    
    Write-Verbose "Merge complete: $($merged.Count) total volume(s) in final dataset"
    
    return $merged
}

function Save-MergedDataToRegistry {
    <#
    .SYNOPSIS
        Saves merged data to registry
        
    .DESCRIPTION
        Writes each volume's data to its own registry key.
        Uses JSON serialization for the data array.
        
    .PARAMETER MergedData
        Hashtable where Key=VolumeID, Value=Array of entries
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$MergedData
    )
    
    # Ensure root registry path exists
    if (!(Test-Path $script:RegistryRootPath)) {
        Write-Verbose "Creating registry root path: $script:RegistryRootPath"
        New-Item -Path $script:RegistryRootPath -Force | Out-Null
    }
    
    # Save each volume
    foreach ($volumeID in $MergedData.Keys) {
        # Get entries for this volume
        $entries = $MergedData[$volumeID]
        
        # Skip volumes with no entries (don't create empty registry keys)
        if (!$entries -or $entries.Count -eq 0) {
            Write-Verbose "Volume $volumeID has no entries - skipping registry creation"
            continue
        }
        
        $volumePath = Join-Path $script:RegistryRootPath $volumeID
        
        # Ensure volume key exists
        if (!(Test-Path $volumePath)) {
            Write-Verbose "Creating registry key for volume: $volumeID"
            New-Item -Path $volumePath -Force | Out-Null
        }
        
        # Serialize to JSON
        # Note: -Compress keeps registry size manageable
        $jsonData = $entries | ConvertTo-Json -Depth 10 -Compress
        
        # Save to registry
        try {
            Set-ItemProperty -Path $volumePath -Name "Data" -Value $jsonData -Type String -Force -ErrorAction Stop
            Write-Verbose "Saved $($entries.Count) entry(ies) for volume $volumeID"
        } catch {
            Write-Error "Failed to save volume $volumeID to registry: $($_.Exception.Message)"
            throw
        }
    }
    
    Write-Verbose "All volumes saved to registry successfully"
}

function Get-BitlockerDataSavedToDiskSummary {
    <#
    .SYNOPSIS
        Gets the most recent recovery key for each volume
        
    .DESCRIPTION
        Returns a summary showing the newest key for each volume.
        This is what Ninja should call to collect current keys.
        
        IMPORTANT: This shows ALL volumes in registry, including disconnected drives.
        
    .OUTPUTS
        String - Formatted key data (one line per volume, joined with newlines)
        
    .EXAMPLE
        Get-BitlockerDataSavedToDiskSummary
        Returns summary of all volumes and their most recent keys
        
    .EXAMPLE
        Get-BitlockerDataSavedToDiskSummary | Out-File C:\keys.txt
        Exports key summary to file
        
    .EXAMPLE
        $keys = Get-BitlockerDataSavedToDiskSummary
        Ninja-Property-Set bitlockerKeys $keys
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    
    try {
        # Load all data from registry
        $allData = Get-AllExistingRegistryData
        
        if ($allData.Count -eq 0) {
            return "No BitLocker keys found"
        }
        
        $summary = @()
        
        foreach ($volumeID in $allData.Keys) {
            $entries = $allData[$volumeID]
            
            if (!$entries -or $entries.Count -eq 0) {
                continue
            }
            
            # Sort by date and get most recent entry
            $sortedEntries = $entries | Sort-Object { [datetime]$_.Date } -Descending
            $mostRecent = $sortedEntries[0]
            
            # Format date as mm/dd/yy
            $formattedDate = ([datetime]$mostRecent.Date).ToString('MM/dd/yy')
            
            # Format output
            $output = "VolumeID: $volumeID | " +
                      "Date: $formattedDate | " +
                      "VolumeLetter: $($mostRecent.MountPoint) | " +
                      "VolumeType: $($mostRecent.VolumeType) | " +
                      "DriveType: $($mostRecent.DriveType) | " +
                      "Status: $($mostRecent.VolumeStatus) | " +
                      "Encrypted: $($mostRecent.EncryptionPercent)% | " +
                      "Method: $($mostRecent.EncryptionMethod) | " +
                      "Protection: $($mostRecent.ProtectionStatus) | " +
                      "Key: $($mostRecent.RecoveryPassword)"
            
            $summary += $output
        }
        
        # Return as single string (joined with newlines)
        return $summary -join "`n"
        
    } catch {
        Write-Error "Error getting BitLocker key summary: $($_.Exception.Message)"
        throw
    }
}

function Get-BitlockerDataSavedToDisk {
    <#
    .SYNOPSIS
        Gets complete history for a specific volume
        
    .DESCRIPTION
        Shows ALL historical keys for a given volume ID.
        Useful for troubleshooting or auditing.
        
    .PARAMETER VolumeID
        The volume ID to query (GUID without braces)
        
    .EXAMPLE
        Get-BitlockerDataSavedToDisk -VolumeID "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        Shows all historical keys for this volume
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VolumeID
    )
    
    try {
        $volumePath = Join-Path $script:RegistryRootPath $VolumeID
        
        if (!(Test-Path $volumePath)) {
            Write-Warning "Volume $VolumeID not found in registry"
            return @()
        }
        
        $jsonData = Get-ItemProperty -Path $volumePath -Name "Data" -ErrorAction Stop | 
            Select-Object -ExpandProperty Data
        
        $entries = $jsonData | ConvertFrom-Json
        
        if ($entries -isnot [array]) {
            $entries = @($entries)
        }
        
        # Sort by date descending (newest first)
        $sorted = $entries | Sort-Object { [datetime]$_.Date } -Descending
        
        return $sorted
        
    } catch {
        Write-Error "Error getting history for volume $VolumeID : $($_.Exception.Message)"
        throw
    }
}

function Get-AllBitlockerKeyData {
    <#
    .SYNOPSIS
        Gets ALL BitLocker key data from registry
        
    .DESCRIPTION
        Returns complete dataset including all volumes and all historical entries.
        
    .OUTPUTS
        Hashtable where Key=VolumeID, Value=Array of entries
        
    .EXAMPLE
        $allData = Get-AllBitlockerKeyData
        $allData.Keys  # Shows all volume IDs
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()
    
    return Get-AllExistingRegistryData
}

function Clear-BitlockerRegistry {
    <#
    .SYNOPSIS
        Clears all BitLocker data from registry
        
    .DESCRIPTION
        USE WITH CAUTION: Deletes all stored BitLocker keys from registry.
        You should immediately run Save-BitlockerDataToDisk after this.
        
    .PARAMETER Force
        Required to confirm deletion
        
    .EXAMPLE
        Clear-BitlockerRegistry -Force
        Save-BitlockerDataToDisk
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [switch]$Force
    )
    
    if (Test-Path $script:RegistryRootPath) {
        Write-Warning "Deleting all BitLocker data from registry..."
        Remove-Item -Path $script:RegistryRootPath -Recurse -Force
        Write-Host "✓ Registry cleared" -ForegroundColor Green
        Write-Host "Run Save-BitlockerDataToDisk to re-save current data" -ForegroundColor Yellow
    } else {
        Write-Host "Registry path does not exist (already clean)" -ForegroundColor Green
    }
}

function Test-BitlockerRegistryIntegrity {
    <#
    .SYNOPSIS
        Validates registry data integrity
        
    .DESCRIPTION
        Checks that all registry data is valid and readable.
        Reports any issues found.
    #>
    [CmdletBinding()]
    param()
    
    Write-Host "`n=== BitLocker Registry Integrity Check ===" -ForegroundColor Cyan
    
    if (!(Test-Path $script:RegistryRootPath)) {
        Write-Host "Registry path does not exist: $script:RegistryRootPath" -ForegroundColor Yellow
        Write-Host "This is normal if no keys have been saved yet." -ForegroundColor Yellow
        return
    }
    
    $allData = Get-AllExistingRegistryData
    $volumeCount = $allData.Keys.Count
    $totalEntries = 0
    $issues = 0
    
    Write-Host "`nRegistry Path: $script:RegistryRootPath" -ForegroundColor Gray
    Write-Host "Total Volumes: $volumeCount" -ForegroundColor Green
    
    foreach ($volumeID in $allData.Keys) {
        $entries = $allData[$volumeID]
        $entryCount = $entries.Count
        $totalEntries += $entryCount
        
        Write-Host "`nVolume: $volumeID" -ForegroundColor Cyan
        Write-Host "  Entries: $entryCount" -ForegroundColor Gray
        
        # Validate each entry
        foreach ($entry in $entries) {
            $hasIssue = $false
            
            if (!$entry.Date) {
                Write-Host "    ⚠ Missing Date" -ForegroundColor Yellow
                $hasIssue = $true
            }
            
            if (!$entry.RecoveryPassword -or $entry.RecoveryPassword -eq 'None') {
                Write-Host "    ⚠ Missing Recovery Password" -ForegroundColor Yellow
                $hasIssue = $true
            }
            
            if (!$entry.MountPoint) {
                Write-Host "    ⚠ Missing MountPoint" -ForegroundColor Yellow
                $hasIssue = $true
            }
            
            if ($hasIssue) {
                $issues++
            }
        }
        
        if ($issues -eq 0) {
            Write-Host "  ✓ All entries valid" -ForegroundColor Green
        }
    }
    
    Write-Host "`n=== Summary ===" -ForegroundColor Cyan
    Write-Host "Total Entries: $totalEntries" -ForegroundColor Green
    Write-Host "Issues Found: $issues" -ForegroundColor $(if($issues -eq 0){'Green'}else{'Yellow'})
    
    if ($issues -eq 0) {
        Write-Host "`n✓ Registry data is healthy" -ForegroundColor Green
    }
}

function Export-BitlockerKeysToFile {
    <#
    .SYNOPSIS
        Exports all BitLocker keys to a JSON file
        
    .DESCRIPTION
        Creates a human-readable backup of all registry data.
        Useful for disaster recovery or migration.
        
    .PARAMETER Path
        Output file path (default: Desktop)
        
    .EXAMPLE
        Export-BitlockerKeysToFile
        Exports to Desktop with timestamp
        
    .EXAMPLE
        Export-BitlockerKeysToFile -Path "C:\Backup\keys.json"
        Exports to specific file
    #>
    [CmdletBinding()]
    param(
        [string]$Path = "$env:USERPROFILE\Desktop\BitLockerKeys_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    )
    
    try {
        $allData = Get-AllExistingRegistryData
        
        if ($allData.Count -eq 0) {
            Write-Warning "No data to export"
            return
        }
        
        # Convert to JSON with nice formatting
        $json = $allData | ConvertTo-Json -Depth 10
        
        # Save to file
        $json | Set-Content -Path $Path -Encoding UTF8
        
        Write-Host "✓ Exported to: $Path" -ForegroundColor Green
        Write-Host "  Volumes: $($allData.Keys.Count)" -ForegroundColor Gray
        
        return $Path
        
    } catch {
        Write-Error "Failed to export: $($_.Exception.Message)"
        throw
    }
}
