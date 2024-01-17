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
    Get-Disk | Where-Object { $_.BusType -ne 'USB' } | Get-Partition | Get-Volume | Where-Object { $_.DriveType -like 'fixed' -and $_.DriveLetter }
}

function Get-ExternalVolumes {
    Get-Disk | Where-Object { $_.BusType -eq 'USB' } | Get-Partition | Get-Volume | Where-Object { $_.DriveLetter }
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
        # Removing ':' so values match
        $sysDrive = $env:SystemDrive -replace ':',''
        if ($volume -ne $sysDrive) {
            Enable-BitLockerAutoUnlock -Mountpoint $volume
        }
    }
}

function Enable-InternalUsedSpaceEncryption {
   Get-InternalVolumes | ForEach {
        $volume = $_.DriveLetter
        Enable-Bitlocker -MountPoint $volume -EncryptionMethod Aes256 -RecoveryPasswordProtector -SkipHardwareTest -UsedSpaceOnly -ErrorAction Stop
        # Removing ':' so values match
        $sysDrive = $env:SystemDrive -replace ':',''
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
}

function Enable-SelectVolumeUsedSpaceEncryption {
    param (
        [string]$MountPoint
    )

    Enable-Bitlocker -MountPoint $MountPoint -EncryptionMethod Aes256 -RecoveryPasswordProtector -SkipHardwareTest -UsedSpaceOnly -ErrorAction Stop
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

    if ($osName -like '*Pro*' -or $osName -like '*Enterprise*' -or $osName -like '*Education*') {
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
        Confirm the following condtions are met:
            - OS is supported
            - TPM is present
            - TPM is enabled
            - TPM is activated
            - TPM is owned
            - All volumes you specify are encrypted
            - The Encrypted Method is what you spcify on all volumes
    #>

    [CmdletBinding()]

    Param(
        [Parameter(
            HelpMessage='Set the expected encryption method'
        )]
        [ValidateSet('Aes128', 'Aes256', 'XtsAes128', 'XtsAes256')]
        [string]$ExpectedEncryptionMethod = 'Aes256',

        [Parameter(
            HelpMessage='Set the types of volumes that should be encrypted'
        )]
        [ValidateSet('InternalOnly', 'InternalAndExternal')]
        [string]$WhatShouldBeEncrypted = 'InternalOnly'
    )


    switch ($WhatShouldBeEncrypted) {
        'InternalOnly'          { $volumeType = 'Internal' }
        'InternalAndExternal'   { $volumeType =  'Internal', 'External'}
    }

    try {
        Confirm-EncryptionReadiness

        switch ($WhatShouldBeEncrypted) {
            'InternalOnly'          { $volumes = Get-UnencryptedInternalVolumes }
            'InternalAndExternal'   { $volumes = Get-AllUnencryptedVolumes }
        }

        if ($volumes) {
            throw "Found unencrypted volumes: $volumes"
        }

        $volumes | ForEach {
            if ($_.EncryptionMethod -ne $ExpectedEncryptionMethod) {
                throw "Expected [$ExpectedEncryptionMethod], found [$($_.EncryptionMethod)]"
            }
        }

        # This means we didn't throw, so good to go
        return $true
    } catch {
        # We have exactly what is wrong sitting in $_ here, but I like having a truthy/falsy out for pass/fail
        return $false
    }
}

function Set-EnforceBestPracticeEncryption {
    Param(
        [Parameter(
            HelpMessage='Set the expected encryption method'
        )]
        [ValidateSet('Aes128', 'Aes256', 'XtsAes128', 'XtsAes256')]
        [string]$ExpectedEncryptionMethod = 'Aes256',

        [Parameter(
            HelpMessage='Set the types of volumes that should be encrypted'
        )]
        [ValidateSet('InternalOnly', 'InternalAndExternal')]
        [string]$WhatShouldBeEncrypted = 'InternalOnly'
    )

    Confirm-EncryptionReadiness -Remediate $true

    switch ($WhatShouldBeEncrypted) {
        'InternalOnly'          { $volumes = Get-InternalVolumes | Get-BitlockerData }
        'InternalAndExternal'   { $volumes = Get-BitlockerData }
    }

    $volumes | ForEach {
        if ($_.VolumeStatus -eq 'FullyDecrypted') {
            Write-Output "Best practice misalignment: Volume letter [$($_.MountPoint)] is not encrypted"
            Enable-SelectVolumeFullDiskEncryption -MountPoint $_.MountPoint
            return "Initiated encryption on volume letter [$($_.MountPoint)]"
        } 

        if ($_.VolumeStatus -eq 'EncryptionPaused' -or $_.VolumeStatus -eq 'PartiallyEncrypted') {
            Write-Output "Best practice misalignment: Volume letter [$($_.MountPoint)] had encryption paused"
            Resume-BitLocker -MountPoint $_.MountPoint -ErrorAction Stop
            return "Resumed protection on volume letter [$($_.VolumeStatus)]"
        }

        if ($_.VolumeStatus -eq 'DecryptionPaused' -or $_.VolumeStatus -eq 'PartiallyDecrypted') {
            Write-Output "Best practice misalignment: Volume letter [$($_.MountPoint)] had decryption paused"
            Disable-BitLocker -MountPoint $_.MountPoint -ErrorAction Stop
            return "Resumed decryption on volume letter [$($_.VolumeStatus)]"
        }

        if ($_.EncryptionMethod -ne $ExpectedEncryptionMethod) {
            Write-Output "Best practice misalignment: Volume letter [$($_.MountPoint)] has encryption method of [$($_.EncryptionMethod)] when the expected method is $ExpectedEncryptionMethod" 
            Disable-Bitlocker -MountPoint $_.MountPoint -ErrorAction Stop
            return "Initiated decryption of volume letter [$($_.VolumeStatus)]"
        }

        Get-BitlockerData

        return "Confirmed volume [$($_.VolumeStatus) is in best practice alignment!"
    }
}
