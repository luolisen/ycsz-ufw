# Pure validation shared by the maintenance scripts and isolated tests.
function Assert-ProtectionFixtureChild([string]$Fixture,[string]$Candidate) {
    $root = [IO.Path]::GetFullPath($Fixture).TrimEnd('\')
    $path = [IO.Path]::GetFullPath($Candidate)
    if (!$path.StartsWith($root + '\',[StringComparison]::OrdinalIgnoreCase)) {
        throw "Dynamic path must be strictly inside the disposable fixture: $path"
    }
}

function Add-ProtectionFixtureNativeType {
    if ('YcszFixtureBoundaryNative' -as [type]) { return }
    Add-Type @'
using System;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
public static class YcszFixtureBoundaryNative {
    [StructLayout(LayoutKind.Sequential)]
    public struct ByHandleFileInformation {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct FileDispositionInfo {
        public byte DeleteFile;
    }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool GetFileInformationByHandle(SafeFileHandle file, out ByHandleFileInformation info);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern bool CreateDirectory(string path, IntPtr security);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern bool CreateHardLink(string link, string existing, IntPtr security);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern bool MoveFileEx(string existing, string replacement, uint flags);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool SetFileInformationByHandle(SafeFileHandle file, int fileInformationClass, ref FileDispositionInfo info, uint size);
    [DllImport("kernel32.dll", EntryPoint="SetFileInformationByHandle", SetLastError=true)]
    static extern bool SetFileInformationByHandleRaw(SafeFileHandle file, int fileInformationClass, IntPtr info, uint size);
    public static bool RenameFileByHandle(SafeFileHandle file, string replacement, out int error) {
        byte[] name = Encoding.Unicode.GetBytes(replacement);
        int rootOffset = 4 + (IntPtr.Size == 8 ? 4 : 0);
        int lengthOffset = rootOffset + IntPtr.Size;
        int nameOffset = lengthOffset + 4;
        IntPtr buffer = Marshal.AllocHGlobal(nameOffset + name.Length);
        try {
            for (int i = 0; i < nameOffset + name.Length; i++) Marshal.WriteByte(buffer, i, 0);
            Marshal.WriteInt32(buffer, 0, 0);
            Marshal.WriteIntPtr(buffer, rootOffset, IntPtr.Zero);
            Marshal.WriteInt32(buffer, lengthOffset, name.Length);
            Marshal.Copy(name, 0, IntPtr.Add(buffer, nameOffset), name.Length);
            bool result = SetFileInformationByHandleRaw(file, 3, buffer, checked((uint)(nameOffset + name.Length)));
            error = Marshal.GetLastWin32Error();
            return result;
        } finally { Marshal.FreeHGlobal(buffer); }
    }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern uint QueryDosDevice(string device, StringBuilder target, uint max);
}
'@
}

function Get-ProtectionFixtureWin32Exception([int]$Code,[string]$Message) {
    if ($Code -le 0) { return New-Object System.InvalidOperationException($Message) }
    return New-Object System.ComponentModel.Win32Exception($Code,$Message)
}

function Get-ProtectionFixturePathComponents([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path)
    if ($full -notmatch '^[A-Za-z]:\\') { throw "Dynamic fixture paths must use a local drive: $full" }
    $root = [IO.Path]::GetPathRoot($full)
    $components = New-Object 'System.Collections.Generic.List[string]'
    [void]$components.Add($root)
    $rest = $full.Substring($root.Length).Trim('\')
    if (![string]::IsNullOrWhiteSpace($rest)) {
        $current = $root.TrimEnd('\')
        foreach ($part in $rest.Split('\',[StringSplitOptions]::RemoveEmptyEntries)) {
            $current = Join-Path $current $part
            [void]$components.Add($current)
        }
    }
    return $components.ToArray()
}

function Get-ProtectionFixtureEntity([string]$Path,[uint32]$Share=3) {
    Add-ProtectionFixtureNativeType
    $full = [IO.Path]::GetFullPath($Path)
    $flags = 0x02000000 -bor 0x00200000
    $handle = [YcszFixtureBoundaryNative]::CreateFile($full,0x00000080,$Share,[IntPtr]::Zero,3,$flags,[IntPtr]::Zero)
    $openError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    if ($null -eq $handle -or $handle.IsInvalid) {
        if ($null -ne $handle) { $handle.Dispose() }
        throw (Get-ProtectionFixtureWin32Exception $openError ("Could not open fixture entity: " + $full))
    }
    $info = New-Object YcszFixtureBoundaryNative+ByHandleFileInformation
    $read = [YcszFixtureBoundaryNative]::GetFileInformationByHandle($handle,[ref]$info)
    $readError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    if (!$read) {
        $handle.Dispose()
        throw (Get-ProtectionFixtureWin32Exception $readError ("Could not query fixture entity: " + $full))
    }
    $fileIndex = ([uint64]$info.FileIndexHigh -shl 32) -bor [uint64]$info.FileIndexLow
    $length = ([uint64]$info.FileSizeHigh -shl 32) -bor [uint64]$info.FileSizeLow
    return [pscustomobject]@{
        Path=$full; Handle=$handle; Attributes=[uint32]$info.FileAttributes
        VolumeSerial=[uint32]$info.VolumeSerialNumber; FileIndex=$fileIndex
        NumberOfLinks=[uint32]$info.NumberOfLinks; Length=$length
        IsDirectory=(([uint32]$info.FileAttributes -band 0x10) -ne 0)
    }
}

function Get-ProtectionFixtureHandleEntity($Handle,[string]$Path) {
    Add-ProtectionFixtureNativeType
    if ($null -eq $Handle -or $Handle.IsInvalid) { throw "Fixture handle is invalid: $Path" }
    $info = New-Object YcszFixtureBoundaryNative+ByHandleFileInformation
    $read = [YcszFixtureBoundaryNative]::GetFileInformationByHandle($Handle,[ref]$info)
    $readError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    if (!$read) { throw (Get-ProtectionFixtureWin32Exception $readError ("Could not query fixture handle: " + $Path)) }
    $fileIndex = ([uint64]$info.FileIndexHigh -shl 32) -bor [uint64]$info.FileIndexLow
    $length = ([uint64]$info.FileSizeHigh -shl 32) -bor [uint64]$info.FileSizeLow
    return [pscustomobject]@{
        Path=[IO.Path]::GetFullPath($Path); Attributes=[uint32]$info.FileAttributes
        VolumeSerial=[uint32]$info.VolumeSerialNumber; FileIndex=$fileIndex
        NumberOfLinks=[uint32]$info.NumberOfLinks; Length=$length
        IsDirectory=(([uint32]$info.FileAttributes -band 0x10) -ne 0)
    }
}

function Close-ProtectionFixtureEntity($Entity) {
    if ($null -ne $Entity -and $null -ne $Entity.Handle) {
        try { $Entity.Handle.Dispose() } catch { }
    }
}

function New-ProtectionFixtureOwnedRecord([string]$Path,[string]$Kind,$Entity) {
    if ($null -eq $Entity) { throw "Cannot record an owned fixture without an entity: $Path" }
    $record = [ordered]@{
        Path=[IO.Path]::GetFullPath($Path); Kind=$Kind; VolumeSerial=$Entity.VolumeSerial; FileIndex=$Entity.FileIndex
        Attributes=$Entity.Attributes; NumberOfLinks=$Entity.NumberOfLinks
    }
    if ($Entity.PSObject.Properties.Name -contains 'Length') { $record.Length=$Entity.Length }
    return [pscustomobject]$record
}

function Assert-ProtectionFixtureEntity($Entity,[switch]$AllowMultipleLinks) {
    if ($null -eq $Entity) { throw 'Fixture entity is missing.' }
    if (($Entity.Attributes -band 0x400) -ne 0) { throw "Fixture entity is a reparse point: $($Entity.Path)" }
    if (!$AllowMultipleLinks -and !$Entity.IsDirectory -and $Entity.NumberOfLinks -ne 1) {
        throw "Fixture file has unexpected hard-link count $($Entity.NumberOfLinks): $($Entity.Path)"
    }
    return $Entity
}

function Test-ProtectionFixtureOwnedEntity($Owned,$Entity) {
    if ($null -eq $Owned -or $null -eq $Entity) {
        return [pscustomobject]@{ Matches=$false; Detail='Owned fixture or handle entity is missing.' }
    }
    $isReparse = ($Entity.Attributes -band 0x400) -ne 0
    $kindMatches = switch ([string]$Owned.Kind) {
        'Directory' { $Entity.IsDirectory -and !$isReparse; break }
        'Junction' { $Entity.IsDirectory -and $isReparse; break }
        'File' { !$Entity.IsDirectory -and !$isReparse -and $Entity.NumberOfLinks -eq 1; break }
        'HardLink' { !$Entity.IsDirectory -and !$isReparse; break }
        default { $false; break }
    }
    if (!$kindMatches) {
        return [pscustomobject]@{ Matches=$false; Detail=('Owned fixture type changed or is unsupported: ' + $Owned.Path) }
    }
    if ($Entity.VolumeSerial -ne [uint64]$Owned.VolumeSerial -or $Entity.FileIndex -ne [uint64]$Owned.FileIndex) {
        return [pscustomobject]@{ Matches=$false; Detail='Owned path identity changed; evidence path is retained.' }
    }
    return [pscustomobject]@{ Matches=$true; Detail='Owned path identity matches the entity opened for the operation.' }
}

function New-ProtectionFixtureScope([string]$FixtureRoot,[string[]]$RequiredPaths,[string[]]$AllowMissingLeafPaths,[string[]]$ReadOnlyPaths) {
    Add-ProtectionFixtureNativeType
    $root = [IO.Path]::GetFullPath($FixtureRoot)
    if ($root -notmatch '^[A-Za-z]:\\' -or [IO.Path]::GetPathRoot($root).TrimEnd('\') -eq $root.TrimEnd('\')) {
        throw "Fixture root must be a strict local-drive directory: $root"
    }
    $paths = New-Object 'System.Collections.Generic.List[string]'
    [void]$paths.Add($root)
    foreach ($path in @($RequiredPaths)) {
        if ([string]::IsNullOrWhiteSpace($path)) { throw 'Fixture scope contains an empty required path.' }
        Assert-ProtectionFixtureChild $root $path
        foreach ($component in Get-ProtectionFixturePathComponents $path) { [void]$paths.Add($component) }
    }
    $missing = @($AllowMissingLeafPaths | ForEach-Object { [IO.Path]::GetFullPath($_) })
    $readOnly = @($ReadOnlyPaths | ForEach-Object { [IO.Path]::GetFullPath($_) })
    $entities = New-Object 'System.Collections.Generic.List[object]'
    $seen = @{}
    try {
        foreach ($path in @($paths | Select-Object -Unique)) {
            $isFinalMissingAllowed = $false
            foreach ($candidate in $missing) { if ([string]::Equals($candidate,$path,[StringComparison]::OrdinalIgnoreCase)) { $isFinalMissingAllowed=$true; break } }
            $share = 3
            foreach ($candidate in $readOnly) { if ([string]::Equals($candidate,$path,[StringComparison]::OrdinalIgnoreCase)) { $share=1; break } }
            $entity=$null
            try {
                try { $entity = Get-ProtectionFixtureEntity $path ([uint32]$share) }
                catch {
                    $code = Get-ProtectionNativeErrorCode $_
                    if ($isFinalMissingAllowed -and ($code -eq 2 -or $code -eq 3)) { continue }
                    throw
                }
                Assert-ProtectionFixtureEntity $entity | Out-Null
                if ([string]::Equals($entity.Path,$root,[StringComparison]::OrdinalIgnoreCase) -and !$entity.IsDirectory) { throw "Fixture root is not a directory: $root" }
                $seen[$entity.Path.ToLowerInvariant()]=$true
                [void]$entities.Add($entity)
                $entity=$null
            } finally {
                if ($null -ne $entity) { Close-ProtectionFixtureEntity $entity }
            }
        }
        return [pscustomobject]@{ FixtureRoot=$root; Entities=$entities.ToArray(); Paths=$seen.Keys }
    } catch {
        foreach ($entity in $entities) { Close-ProtectionFixtureEntity $entity }
        throw
    }
}

function Close-ProtectionFixtureScope($Scope) {
    if ($null -eq $Scope -or $null -eq $Scope.Entities) { return }
    foreach ($entity in @($Scope.Entities | Sort-Object -Property Path -Descending)) { Close-ProtectionFixtureEntity $entity }
}

function Test-ProtectionFixturePathEquals([string]$First,[string]$Second) {
    return [string]::Equals([IO.Path]::GetFullPath($First).TrimEnd('\'),[IO.Path]::GetFullPath($Second).TrimEnd('\'),[StringComparison]::OrdinalIgnoreCase)
}

function Assert-ProtectionFixtureManifest($Manifest,[string]$FixtureRoot,[string]$ProtectedRoot,[string]$ProtectedDataRoot,[string]$ServiceImagePath) {
    if ($null -eq $Manifest -or [string]::IsNullOrWhiteSpace([string]$Manifest.FixtureId)) { throw 'Fixture manifest is missing FixtureId.' }
    $id=[guid]::Empty
    if (![guid]::TryParse([string]$Manifest.FixtureId,[ref]$id) -or $id -eq [guid]::Empty) { throw 'Fixture manifest FixtureId is invalid.' }
    foreach ($pair in @(
        @('FixtureRoot',$Manifest.FixtureRoot,$FixtureRoot),
        @('ProtectedRoot',$Manifest.ProtectedRoot,$ProtectedRoot),
        @('ProtectedDataRoot',$Manifest.ProtectedDataRoot,$ProtectedDataRoot),
        @('ServiceImagePath',$Manifest.ServiceImagePath,$ServiceImagePath)
    )) {
        if ([string]::IsNullOrWhiteSpace([string]$pair[1]) -or ![string]::Equals([IO.Path]::GetFullPath([string]$pair[1]).TrimEnd('\'),[IO.Path]::GetFullPath([string]$pair[2]).TrimEnd('\'),[StringComparison]::OrdinalIgnoreCase)) {
            throw "Fixture manifest $($pair[0]) does not match the requested path."
        }
    }
    if ([string]$Manifest.ServiceName -ne 'YcszFirewall') { throw 'Fixture manifest service name is not YcszFirewall.' }
    Assert-ProtectionFixtureChild $FixtureRoot $ProtectedRoot
    Assert-ProtectionFixtureChild $FixtureRoot $ProtectedDataRoot
    Assert-ProtectionFixtureChild $FixtureRoot $ServiceImagePath
    $files=@($Manifest.ProtectedFiles)
    if ($files.Count -eq 0) { throw 'Fixture manifest has no protected sample files.' }
    $seen=@{}
    foreach ($file in $files) {
        if ([string]::IsNullOrWhiteSpace([string]$file.Path) -or $seen.ContainsKey(([IO.Path]::GetFullPath([string]$file.Path)).ToLowerInvariant())) { throw 'Fixture manifest has a missing or duplicate protected file.' }
        $path=[IO.Path]::GetFullPath([string]$file.Path)
        Assert-ProtectionFixtureChild $FixtureRoot $path
        foreach ($field in @('Length','NumberOfLinks','VolumeSerial','FileIndex')) {
            if ($file.PSObject.Properties.Name -notcontains $field) { throw "Fixture manifest protected file metadata is incomplete: $path" }
        }
        $length=[uint64]0; $links=[uint64]0; $volume=[uint64]0; $index=[uint64]0
        if (![uint64]::TryParse([string]$file.Length,[ref]$length) -or
            ![uint64]::TryParse([string]$file.NumberOfLinks,[ref]$links) -or
            ![uint64]::TryParse([string]$file.VolumeSerial,[ref]$volume) -or
            ![uint64]::TryParse([string]$file.FileIndex,[ref]$index)) {
            throw "Fixture manifest protected file metadata is not numeric: $path"
        }
        if ($links -ne 1) { throw "Fixture manifest protected file link count is invalid: $path" }
        if ($index -eq 0 -or $volume -eq 0) { throw "Fixture manifest protected file identity is invalid: $path" }
        $seen[$path.ToLowerInvariant()]=$true
    }
    return $files
}

function ConvertTo-ProtectionFixtureNtPath([string]$Path) {
    Add-ProtectionFixtureNativeType
    $full=[IO.Path]::GetFullPath($Path)
    if ($full -notmatch '^[A-Za-z]:\\') { throw "Fixture path must use a local drive: $full" }
    $drive=$full.Substring(0,2)
    $buffer=New-Object Text.StringBuilder 1024
    $length=[YcszFixtureBoundaryNative]::QueryDosDevice($drive,$buffer,[uint32]$buffer.Capacity)
    $error=[Runtime.InteropServices.Marshal]::GetLastWin32Error()
    if ($length -eq 0) { throw (Get-ProtectionFixtureWin32Exception $error ("QueryDosDevice failed for $drive")) }
    return $buffer.ToString() + $full.Substring(2)
}

function New-ProtectionFixtureDirectory([string]$Path) {
    Add-ProtectionFixtureNativeType
    $full=[IO.Path]::GetFullPath($Path)
    $created=[YcszFixtureBoundaryNative]::CreateDirectory($full,[IntPtr]::Zero)
    $error=[Runtime.InteropServices.Marshal]::GetLastWin32Error()
    if (!$created) { throw (Get-ProtectionFixtureWin32Exception $error ("Fixture directory was not created: " + $full)) }
    $entity=$null
    try {
        $entity=Get-ProtectionFixtureEntity $full
        Assert-ProtectionFixtureEntity $entity | Out-Null
        if (!$entity.IsDirectory) { throw "Created fixture path is not a directory: $full" }
        return New-ProtectionFixtureOwnedRecord $full 'Directory' $entity
    } catch {
        if ($null -ne $entity -and $entity.IsDirectory -and (($entity.Attributes -band 0x400) -eq 0)) {
            $owned=New-ProtectionFixtureOwnedRecord $full 'Directory' $entity
            Close-ProtectionFixtureEntity $entity; $entity=$null
            $decision=Remove-ProtectionFixtureOwnedPath $owned
            if ($decision.Status -ne 'PASS') { throw ("Created directory validation failed and safe handle cleanup was not confirmed: " + $decision.Detail) }
        }
        throw
    }
    finally { if ($null -ne $entity) { Close-ProtectionFixtureEntity $entity } }
}

function New-ProtectionFixtureFile([string]$Path,[byte[]]$Bytes) {
    $full=[IO.Path]::GetFullPath($Path)
    $stream=$null
    $createdOwned=$null
    $failure=$null
    try {
        $stream=New-Object IO.FileStream($full,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::Read)
        $createdEntity=Get-ProtectionFixtureHandleEntity $stream.SafeFileHandle $full
        if (!$createdEntity.IsDirectory -and (($createdEntity.Attributes -band 0x400) -eq 0)) {
            $createdOwned=New-ProtectionFixtureOwnedRecord $full 'File' $createdEntity
        } else {
            throw "Created fixture path is not a regular file: $full"
        }
        if ($null -ne $Bytes -and $Bytes.Length -gt 0) { $stream.Write($Bytes,0,$Bytes.Length); $stream.Flush($true) }
    } catch {
        $failure=$_
    } finally {
        if ($null -ne $stream) { try { $stream.Dispose() } catch { if ($null -eq $failure) { $failure=$_ } } }
    }
    if ($null -ne $failure) {
        if ($null -ne $createdOwned) {
            $decision=Remove-ProtectionFixtureOwnedPath $createdOwned
            if ($decision.Status -ne 'PASS') { throw ("Fixture file creation failed and safe handle cleanup was not confirmed: " + $decision.Detail) }
        }
        throw $failure
    }
    $entity=$null
    try {
        $entity=Get-ProtectionFixtureEntity $full
        Assert-ProtectionFixtureEntity $entity | Out-Null
        if ($entity.IsDirectory) { throw "Created fixture path is a directory: $full" }
        return New-ProtectionFixtureOwnedRecord $full 'File' $entity
    } catch {
        if ($null -ne $entity) { Close-ProtectionFixtureEntity $entity; $entity=$null }
        if ($null -ne $createdOwned) {
            $decision=Remove-ProtectionFixtureOwnedPath $createdOwned
            if ($decision.Status -ne 'PASS') { throw ("Fixture file validation failed and safe handle cleanup was not confirmed: " + $decision.Detail) }
        }
        throw
    } finally { if ($null -ne $entity) { Close-ProtectionFixtureEntity $entity } }
}

function New-ProtectionFixtureHardLink([string]$Path,[string]$Target) {
    Add-ProtectionFixtureNativeType
    $full=[IO.Path]::GetFullPath($Path); $targetFull=[IO.Path]::GetFullPath($Target)
    $created=[YcszFixtureBoundaryNative]::CreateHardLink($full,$targetFull,[IntPtr]::Zero)
    $error=[Runtime.InteropServices.Marshal]::GetLastWin32Error()
    if (!$created) { throw (Get-ProtectionFixtureWin32Exception $error ("Fixture hard link was not created: " + $full)) }
    $entity=$null
    try {
        $entity=Get-ProtectionFixtureEntity $full
        Assert-ProtectionFixtureEntity $entity -AllowMultipleLinks | Out-Null
        if ($entity.IsDirectory -or $entity.NumberOfLinks -lt 2) { throw "Fixture hard link identity was not confirmed: $full" }
        return New-ProtectionFixtureOwnedRecord $full 'HardLink' $entity
    } catch {
        if ($null -ne $entity -and !$entity.IsDirectory -and (($entity.Attributes -band 0x400) -eq 0)) {
            $owned=New-ProtectionFixtureOwnedRecord $full 'HardLink' $entity
            Close-ProtectionFixtureEntity $entity; $entity=$null
            $decision=Remove-ProtectionFixtureOwnedPath $owned
            if ($decision.Status -ne 'PASS') { throw ("Fixture hard-link validation failed and safe handle cleanup was not confirmed: " + $decision.Detail) }
        }
        throw
    } finally { if ($null -ne $entity) { Close-ProtectionFixtureEntity $entity } }
}

function Test-ProtectionFixtureOwnedIdentity($Owned) {
    $entity=$null
    try { $entity=Get-ProtectionFixtureEntity $Owned.Path }
    catch {
        $code=Get-ProtectionNativeErrorCode $_
        if ($code -eq 2 -or $code -eq 3) { return [pscustomobject]@{ Status='PASS'; Exists=$false; Detail='Owned path is already absent.' } }
        return [pscustomobject]@{ Status='ERROR'; Exists=$true; Detail=('Could not re-open owned path; identity was not confirmed: ' + $_.Exception.Message) }
    }
    try {
        $match=Test-ProtectionFixtureOwnedEntity $Owned $entity
        if (!$match.Matches) { return [pscustomobject]@{ Status='ERROR'; Exists=$true; Detail=$match.Detail } }
        return [pscustomobject]@{ Status='PASS'; Exists=$true; Entity=$entity; Detail=$match.Detail }
    } finally { if ($null -ne $entity) { Close-ProtectionFixtureEntity $entity } }
}

function Set-ProtectionFixtureDeleteDisposition($Handle,[string]$Path) {
    Add-ProtectionFixtureNativeType
    $disposition=New-Object YcszFixtureBoundaryNative+FileDispositionInfo
    $disposition.DeleteFile=[byte]1
    $set=[YcszFixtureBoundaryNative]::SetFileInformationByHandle($Handle,4,[ref]$disposition,[uint32]1)
    $error=[Runtime.InteropServices.Marshal]::GetLastWin32Error()
    if (!$set) { throw (Get-ProtectionFixtureWin32Exception $error ('Handle-bound cleanup disposition failed: ' + $Path)) }
    return $true
}

function Get-ProtectionFixtureOwnedPathObservation($Owned) {
    $entity=$null
    try { $entity=Get-ProtectionFixtureEntity $Owned.Path }
    catch {
        $code=Get-ProtectionNativeErrorCode $_
        if ($code -eq 2 -or $code -eq 3) { return [pscustomobject]@{ Status='PASS'; Exists=$false; Matches=$false; Detail='Owned path is absent after handle-bound cleanup.' } }
        return [pscustomobject]@{ Status='ERROR'; Exists=$true; Matches=$false; Detail=('Could not observe the path after handle-bound cleanup: ' + $_.Exception.Message) }
    }
    try {
        $match=Test-ProtectionFixtureOwnedEntity $Owned $entity
        if ($match.Matches) { return [pscustomobject]@{ Status='PASS'; Exists=$true; Matches=$true; Detail=$match.Detail } }
        return [pscustomobject]@{ Status='REPLACED'; Exists=$true; Matches=$false; Detail='The original handle was dispositioned and the path now names a different entity; replacement was retained.' }
    } finally { if ($null -ne $entity) { Close-ProtectionFixtureEntity $entity } }
}

function Remove-ProtectionFixtureOwnedPath($Owned,[scriptblock]$BeforeDelete,[switch]$AllowDeleteShare) {
    if ($null -eq $Owned -or [string]::IsNullOrWhiteSpace([string]$Owned.Path)) {
        return [pscustomobject]@{ Status='ERROR'; Exists=$true; Detail='Owned cleanup requires an explicit path and identity record.' }
    }
    Add-ProtectionFixtureNativeType
    $full=[IO.Path]::GetFullPath([string]$Owned.Path)
    $share=if ($AllowDeleteShare) { [uint32]7 } else { [uint32]3 }
    $handle=$null
    $openedEntity=$null
    $missing=$false
    $failure=$null
    $marked=$false
    try {
        $handle=[YcszFixtureBoundaryNative]::CreateFile($full,[uint32]0x00010080,$share,[IntPtr]::Zero,[uint32]3,[uint32](0x02000000 -bor 0x00200000),[IntPtr]::Zero)
        $openError=[Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if ($null -eq $handle -or $handle.IsInvalid) {
            if ($null -ne $handle) { $handle.Dispose(); $handle=$null }
            if ($openError -eq 2 -or $openError -eq 3) { $missing=$true }
            else { $failure=Get-ProtectionFixtureWin32Exception $openError ('Could not open owned path for handle-bound cleanup: ' + $full) }
        } else {
            $openedEntity=Get-ProtectionFixtureHandleEntity $handle $full
            $match=Test-ProtectionFixtureOwnedEntity $Owned $openedEntity
            if (!$match.Matches) {
                $failure=New-Object System.InvalidOperationException($match.Detail)
            } elseif ($null -ne $BeforeDelete) {
                try { $null=$BeforeDelete.Invoke($handle,$openedEntity) }
                catch { $failure=New-Object System.InvalidOperationException(('Controlled replacement hook failed before handle-bound cleanup: ' + $_.Exception.Message)) }
            }
            if ($null -eq $failure) {
                try { [void](Set-ProtectionFixtureDeleteDisposition $handle $full); $marked=$true }
                catch { $failure=$_ }
            }
        }
    } catch { $failure=$_ }
    finally {
        if ($null -ne $handle) {
            try { $handle.Dispose() } catch { if ($null -eq $failure) { $failure=$_ } }
        }
    }
    if ($missing) { return [pscustomobject]@{ Status='PASS'; Exists=$false; Detail='Owned path was already absent.' } }
    if ($null -ne $failure) {
        $detail=if ($failure -is [System.Management.Automation.ErrorRecord]) { $failure.Exception.Message } elseif ($failure -is [System.Exception]) { $failure.Message } else { [string]$failure }
        return [pscustomobject]@{ Status='ERROR'; Exists=$true; Detail=('Handle-bound cleanup failed for ' + $full + '; evidence path is retained: ' + $detail) }
    }
    if (!$marked) { return [pscustomobject]@{ Status='ERROR'; Exists=$true; Detail=('Handle-bound cleanup did not mark the owned entity: ' + $full) } }
    $after=Get-ProtectionFixtureOwnedPathObservation $Owned
    if ($after.Status -eq 'ERROR') { return [pscustomobject]@{ Status='ERROR'; Exists=$after.Exists; Detail=$after.Detail } }
    if ($after.Matches) { return [pscustomobject]@{ Status='ERROR'; Exists=$true; Detail='Handle-bound cleanup was marked but the same owned entity remained; evidence path is retained.' } }
    if ($after.Exists) { return [pscustomobject]@{ Status='PASS'; Exists=$true; ReplacementDetected=$true; Detail=$after.Detail } }
    return [pscustomobject]@{ Status='PASS'; Exists=$false; Detail='Owned entity was removed by disposition on its verified handle.' }
}

function Assert-ProtectionServiceCommand([string]$Command,[string]$Image) {
    $suffix = '" --service'
    if (!$Command -or !$Image -or !$Command.StartsWith('"') -or !$Command.EndsWith($suffix,[StringComparison]::Ordinal)) {
        throw 'The product service command must quote the image and use only --service.'
    }
    $actual = $Command.Substring(1,$Command.Length - 1 - $suffix.Length)
    if (![string]::Equals($actual,$Image,[StringComparison]::OrdinalIgnoreCase)) {
        throw 'The product service image does not exactly match the fixed installation path.'
    }
}

function Resolve-ProtectionSignTool {
    $command = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    $roots = @(
        (Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'),
        (Join-Path $env:ProgramFiles 'Windows Kits\10\bin')
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }
    $tool = Get-ChildItem -Path $roots -Filter signtool.exe -Recurse -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending | Select-Object -First 1
    if (!$tool) { throw 'signtool.exe was not found; CAT member binding cannot be verified.' }
    return $tool.FullName
}

function Assert-ProtectionCatalogMembers([string]$PackageDirectory) {
    if ([string]::IsNullOrWhiteSpace($PackageDirectory)) { throw 'PackageDirectory is required.' }
    $package = [IO.Path]::GetFullPath($PackageDirectory)
    $inf = Join-Path $package 'YcszProtection.inf'
    $sys = Join-Path $package 'YcszProtection.sys'
    $cat = Join-Path $package 'YcszProtection.cat'
    foreach ($path in @($inf,$sys,$cat)) { if (!(Test-Path -LiteralPath $path -PathType Leaf)) { throw "Protection package member is missing: $path" } }
    $catalogLine = Get-Content -LiteralPath $inf | Where-Object { $_ -match '^\s*CatalogFile\s*=\s*YcszProtection\.cat\s*$' } | Select-Object -First 1
    if (!$catalogLine) { throw 'YcszProtection.inf does not bind exactly to YcszProtection.cat.' }
    $signTool = Resolve-ProtectionSignTool
    foreach ($member in @($inf,$sys)) {
        & $signTool verify /kp /c $cat $member | Out-Host
        if ($LASTEXITCODE -ne 0) { throw "CAT member binding verification failed for $member ($LASTEXITCODE)." }
    }
    return $true
}

function Get-ProtectionDataRoot {
    $common = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
    if ([string]::IsNullOrWhiteSpace($common)) { throw 'CommonApplicationData is unavailable.' }
    return [IO.Path]::GetFullPath((Join-Path $common 'YcszFirewall'))
}

function Assert-ProtectionPackage([string]$PublishedName,$Package) {
    if ($PublishedName -notmatch '^oem[0-9]+\.inf$') { throw 'Expected an OEM INF name, not a path or command option.' }
    if (@($Package).Count -ne 1 -or !$Package -or
        [IO.Path]::GetFileName($Package.OriginalFileName) -ine 'YcszProtection.inf' -or
        $Package.ProviderName -ine 'YCSZ' -or $Package.ClassName -ine 'ActivityMonitor') {
        throw 'The selected driver-store package is not YCSZ protection.'
    }
    if ($Package.PSObject.Properties.Name -contains 'CatalogFile' -and $Package.CatalogFile -ine 'YcszProtection.cat') {
        throw 'The selected driver-store package is not bound to YcszProtection.cat.'
    }
}

function Test-IsProtectionPackage($Package) {
    if ($null -eq $Package) { return $false }
    return [IO.Path]::GetFileName([string]$Package.OriginalFileName) -ieq 'YcszProtection.inf' -and
        [string]$Package.ProviderName -ieq 'YCSZ' -and
        [string]$Package.ClassName -ieq 'ActivityMonitor'
}

function Get-ProtectionPackageName($Package) {
    if ($null -eq $Package -or [string]::IsNullOrWhiteSpace([string]$Package.Driver)) { return $null }
    $name = [IO.Path]::GetFileName([string]$Package.Driver)
    if ($name -notmatch '^oem[0-9]+\.inf$') { return $null }
    return $name.ToLowerInvariant()
}

function Get-ProtectionPackageSnapshot {
    return @(Get-WindowsDriver -Online -ErrorAction Stop | ForEach-Object { $_ })
}

function Get-ProtectionPackageDelta([object[]]$Before,[object[]]$After) {
    $beforeMap=@{}; $afterMap=@{}
    foreach ($package in @($Before)) {
        $name=Get-ProtectionPackageName $package
        if ($name) { $beforeMap[$name]=$package }
    }
    foreach ($package in @($After)) {
        $name=Get-ProtectionPackageName $package
        if ($name) { $afterMap[$name]=$package }
    }
    $newNames=@($afterMap.Keys | Where-Object { !$beforeMap.ContainsKey($_) } | Sort-Object)
    $removedNames=@($beforeMap.Keys | Where-Object { !$afterMap.ContainsKey($_) } | Sort-Object)
    $newPackages=@($newNames | ForEach-Object { $afterMap[$_] })
    $removedPackages=@($removedNames | ForEach-Object { $beforeMap[$_] })
    $beforeProtection=@($beforeMap.Values | Where-Object { Test-IsProtectionPackage $_ })
    $afterProtection=@($afterMap.Values | Where-Object { Test-IsProtectionPackage $_ })
    $newProtection=@($newPackages | Where-Object { Test-IsProtectionPackage $_ })
    $removedProtection=@($removedPackages | Where-Object { Test-IsProtectionPackage $_ })
    $newOther=@($newPackages | Where-Object { !(Test-IsProtectionPackage $_) })
    return [pscustomobject]@{
        Before=@($Before); After=@($After); NewNames=$newNames; RemovedNames=$removedNames
        NewPackages=$newPackages; RemovedPackages=$removedPackages
        BeforeProtection=$beforeProtection; AfterProtection=$afterProtection
        NewProtection=$newProtection; RemovedProtection=$removedProtection; NewOther=$newOther
    }
}

function Assert-ProtectionPackageDelta($Delta,[switch]$AllowNoop) {
    if ($null -eq $Delta) { throw 'Protection package delta is missing.' }
    if (@($Delta.RemovedProtection).Count -gt 0) { throw 'An existing YCSZ protection package disappeared during installation.' }
    if (@($Delta.NewOther).Count -gt 0) { throw 'An unrelated driver package appeared; no package will be deleted automatically.' }
    if (@($Delta.NewProtection).Count -gt 1) { throw 'More than one new YCSZ protection package appeared; refusing ambiguous rollback.' }
    if (!$AllowNoop -and @($Delta.BeforeProtection).Count -eq 0 -and @($Delta.NewProtection).Count -eq 0) {
        throw 'No new YCSZ protection package was observable after installation.'
    }
    if (@($Delta.AfterProtection).Count -eq 0) { throw 'No YCSZ protection package is present after installation.' }
    return $Delta
}

function New-ProtectionRollbackPlan($Before,$After,[bool]$DriverWasRegistered,[bool]$ApplicationWasRunning) {
    $delta=Get-ProtectionPackageDelta $Before $After
    Assert-ProtectionPackageDelta $delta -AllowNoop:($DriverWasRegistered -and @($delta.NewProtection).Count -eq 0) | Out-Null
    return [pscustomobject]@{
        Delta=$delta
        NewProtectionNames=@($delta.NewProtection | ForEach-Object { Get-ProtectionPackageName $_ })
        ExistingProtectionNames=@($delta.BeforeProtection | ForEach-Object { Get-ProtectionPackageName $_ })
        RestoreOldPackage=(@($delta.BeforeProtection).Count -gt 0)
        RemoveNewRegistration=(-not $DriverWasRegistered)
        RestartApplication=$ApplicationWasRunning
    }
}

function Assert-ProtectionRollbackStopped($ApplicationService,$DriverService) {
    foreach ($service in @($ApplicationService,$DriverService)) {
        if ($null -ne $service -and $service.Status -ne 'Stopped') {
            throw 'Rollback may not alter configuration or remove files while a product service is not stopped.'
        }
    }
}

function Get-ProtectionNativeErrorCode($ErrorRecord) {
    $exception = $null
    if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) {
        $exception = $ErrorRecord.Exception
    } elseif ($ErrorRecord -is [System.Exception]) {
        $exception = $ErrorRecord
    }
    while ($null -ne $exception) {
        if ($exception -is [System.ComponentModel.Win32Exception]) {
            return [int]$exception.NativeErrorCode
        }
        $nativeProperty = $exception.PSObject.Properties['NativeErrorCode']
        if ($null -ne $nativeProperty) {
            try { return [int]$nativeProperty.Value } catch { }
        }
        # HRESULT is signed; casting a negative Int32 to UInt32 throws in
        # PowerShell. Reinterpret its bits instead of converting its value.
        $hresult = [BitConverter]::ToUInt32([BitConverter]::GetBytes([int]$exception.HResult),0)
        if (($hresult -band [uint32]4294901760) -eq [uint32]2147942400) {
            return [int]($hresult -band [uint32]0x0000FFFF)
        }
        $exception = $exception.InnerException
    }
    return $null
}

function Get-ProtectionWin32ErrorLabel([int]$Code) {
    $hex = ('0x{0:X8}' -f ([uint32]$Code))
    switch ($Code) {
        2 { return "ERROR_FILE_NOT_FOUND ($Code/$hex)" }
        5 { return "ERROR_ACCESS_DENIED ($Code/$hex)" }
        32 { return "ERROR_SHARING_VIOLATION ($Code/$hex)" }
        145 { return "ERROR_DIR_NOT_EMPTY ($Code/$hex)" }
        50 { return "ERROR_NOT_SUPPORTED ($Code/$hex)" }
        87 { return "ERROR_INVALID_PARAMETER ($Code/$hex)" }
        120 { return "ERROR_CALL_NOT_IMPLEMENTED ($Code/$hex)" }
        default { return "Win32 error $Code/$hex" }
    }
}

function Resolve-ProtectionDynamicNativeFailure([int]$Code,[string]$ExpectedStage,[string]$ActualStage,[bool]$ControlSucceeded) {
    $label = Get-ProtectionWin32ErrorLabel $Code
    if ($Code -eq 50 -or $Code -eq 120) {
        return [pscustomobject]@{ Status='BLOCKED'; Detail=("The platform or filesystem does not support {0}: {1}" -f $ActualStage,$label) }
    }
    if (!$ControlSucceeded) {
        return [pscustomobject]@{ Status='ERROR'; Detail=("Control precondition failed before {0}: {1}" -f $ActualStage,$label) }
    }
    if ($ExpectedStage -ne $ActualStage) {
        return [pscustomobject]@{ Status='ERROR'; Detail=("Native error was captured at unexpected stage {0}; expected {1}: {2}" -f $ActualStage,$ExpectedStage,$label) }
    }
    switch ($Code) {
        5 { return [pscustomobject]@{ Status='PASS'; Detail=("Expected protection denial at {0}: {1}" -f $ActualStage,$label) } }
        87 { return [pscustomobject]@{ Status='ERROR'; Detail=("The dynamic call supplied an invalid parameter at {0}: {1}" -f $ActualStage,$label) } }
        32 { return [pscustomobject]@{ Status='ERROR'; Detail=("The fixture has a sharing conflict at {0}; this is not protection evidence: {1}" -f $ActualStage,$label) } }
        2 { return [pscustomobject]@{ Status='ERROR'; Detail=("The fixture path is missing at {0}; this is not protection evidence: {1}" -f $ActualStage,$label) } }
        default { return [pscustomobject]@{ Status='ERROR'; Detail=("Unexpected native error at {0}; this is not protection evidence: {1}" -f $ActualStage,$label) } }
    }
}

function Resolve-ProtectionDynamicException($ErrorRecord,[string]$ExpectedStage,[string]$ActualStage,[bool]$ControlSucceeded) {
    $code = Get-ProtectionNativeErrorCode $ErrorRecord
    if ($null -eq $code) {
        $message = if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) { $ErrorRecord.Exception.Message } else { [string]$ErrorRecord }
        return [pscustomobject]@{ Status='ERROR'; Detail=("No reliable Win32 error was captured at {0}: {1}" -f $ActualStage,$message) }
    }
    return Resolve-ProtectionDynamicNativeFailure $code $ExpectedStage $ActualStage $ControlSucceeded
}

function Resolve-ProtectionCleanupFailure([string]$Path,[string]$Detail) {
    return [pscustomobject]@{ Status='ERROR'; Detail=('Cleanup failed for {0}. Evidence path is retained. {1}' -f $Path,$Detail) }
}

function Test-ProtectionExpectedUnloadRejection([int]$ExitCode,[string]$Output,[bool]$FilterStillPresent) {
    if ($ExitCode -eq 0) {
        return [pscustomobject]@{ Status='FAIL'; Detail='fltmc unload succeeded while the control handle was open.' }
    }
    if (!$FilterStillPresent) {
        return [pscustomobject]@{ Status='ERROR'; Detail='The unload command was non-zero, but the target filter could not be confirmed as still present.' }
    }
    if ($Output -match '(?i)STATUS_FLT_DO_NOT_DETACH|ERROR_FLT_DO_NOT_DETACH|0xC01C0010|0x801F0010') {
        return [pscustomobject]@{ Status='PASS'; Detail='fltmc reported STATUS_FLT_DO_NOT_DETACH and the target filter remained present.' }
    }
    return [pscustomobject]@{ Status='ERROR'; Detail=('fltmc returned a non-zero result without the expected STATUS_FLT_DO_NOT_DETACH evidence: ' + $Output.Trim()) }
}
