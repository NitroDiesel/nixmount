# End-to-end on a real Windows machine: the real service, WinFsp and drive letters. The
# images it leaves behind go to the Linux job, where e2fsck and btrfs check judge them.
param([string]$Exe, [string]$Out)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force $Out | Out-Null

function Expand-Fixture($name) {
    $src = [IO.File]::OpenRead("tests/fixtures/$name.img.gz")
    $gz = New-Object IO.Compression.GZipStream($src, [IO.Compression.CompressionMode]::Decompress)
    $dst = [IO.File]::Create("$Out/$name.img")
    $gz.CopyTo($dst)
    $dst.Close(); $gz.Close(); $src.Close()
    (Resolve-Path "$Out/$name.img").Path
}

function Check($what, $ok) {
    if (-not $ok) { throw "FAILED: $what" }
    "ok: $what"
}

# Device events settle over a few seconds.
function Wait-For($condition) {
    for ($i = 0; $i -lt 30; $i++) {
        if (& $condition) { return $true }
        Start-Sleep -Seconds 1
    }
    $false
}

& $Exe service install
if ($LASTEXITCODE) { throw 'service install failed' }

foreach ($item in @(@('ext4-default', 'K'), @('btrfs-default', 'L'))) {
    $name, $d = $item
    $img = Expand-Fixture $name
    & $Exe mount $img "${d}:" --rw
    if ($LASTEXITCODE) { throw "mount failed for $name" }
    $root = "${d}:\"

    Check "$name lists seeded files" ((Get-Content "${root}hello.txt") -eq 'hello from linux')
    Check "$name reports its filesystem" ((fsutil fsinfo volumeinfo "${d}:") -match $name.Split('-')[0].ToUpper())

    # Ordinary application behaviour.
    New-Item -ItemType Directory "${root}e2e" | Out-Null
    1..300 | ForEach-Object { Set-Content "${root}e2e\file$_.txt" "content $_" }
    Check "$name directory listing" ((Get-ChildItem "${root}e2e").Count -eq 300)
    Copy-Item "$env:WINDIR\notepad.exe" "${root}e2e\copy.exe"
    Check "$name file copy is byte-exact" ((Get-FileHash "$env:WINDIR\notepad.exe").Hash -eq (Get-FileHash "${root}e2e\copy.exe").Hash)
    Rename-Item "${root}e2e\file1.txt" 'renamed.txt'
    Move-Item "${root}e2e\file2.txt" "${root}moved.txt"
    Remove-Item "${root}e2e\file3.txt"
    Check "$name rename, move and delete" ((Test-Path "${root}e2e\renamed.txt") -and (Test-Path "${root}moved.txt") -and -not (Test-Path "${root}e2e\file3.txt"))

    Check "$name follows a symbolic link" ((Get-Content "${root}link") -eq 'hello from linux')

    # A full disk has to fail loudly at write time, not vanish during write-back.
    $failed = $false
    try {
        $chunk = New-Object byte[] (1MB)
        $f = [IO.File]::OpenWrite("${root}fill.bin")
        for ($i = 0; $i -lt 400; $i++) { $f.Write($chunk, 0, $chunk.Length) }
        $f.Close()
    } catch { $failed = $true; if ($f) { try { $f.Dispose() } catch {} } }
    Check "$name reports disk full" $failed
    Remove-Item "${root}fill.bin" -ErrorAction SilentlyContinue

    & $Exe scrub "${d}:"
    if ($LASTEXITCODE) { throw "scrub failed for $name" }
    & $Exe unmount "${d}:"
    if ($LASTEXITCODE) { throw "unmount failed for $name" }
    Check "$name drive letter is gone" (-not (Test-Path $root))
}

# Read-only mounts must not change a single byte.
$img = Expand-Fixture 'ext3-1k'
$before = (Get-FileHash $img).Hash
& $Exe mount $img 'M:'
Check 'read-only mount serves files' ((Get-Content 'M:\hello.txt') -eq 'hello from linux')
$blocked = $false
try { Set-Content 'M:\nope.txt' 'x' -ErrorAction Stop } catch { $blocked = $true }
Check 'read-only mount refuses writes' $blocked
& $Exe unmount 'M:'
Check 'read-only mount left the image untouched' ($before -eq (Get-FileHash $img).Hash)

# Raw partition access, the real-disk path, on a virtual disk so nothing real is touched.
# A fixed VHD is a plain disk image, so the filesystem can be placed with ordinary file I/O.
$vhd = Join-Path (Resolve-Path $Out).Path 'disk.vhd'
$create = Join-Path (Resolve-Path $Out).Path 'create.txt'
$attach = Join-Path (Resolve-Path $Out).Path 'attach.txt'
$detach = Join-Path (Resolve-Path $Out).Path 'detach.txt'
"create vdisk file=`"$vhd`" maximum=64 type=fixed`nselect vdisk file=`"$vhd`"`nattach vdisk`nconvert mbr`ncreate partition primary id=83`ndetach vdisk" |
    Set-Content $create -Encoding ascii
"select vdisk file=`"$vhd`"`nattach vdisk" | Set-Content $attach -Encoding ascii
"select vdisk file=`"$vhd`"`ndetach vdisk" | Set-Content $detach -Encoding ascii
diskpart /s $create | Out-Null
if ($LASTEXITCODE) { throw 'could not create the virtual disk' }

$fixture = Expand-Fixture 'ext4-default'
$image = [IO.File]::ReadAllBytes($fixture)
$f = [IO.File]::Open($vhd, 'Open', 'ReadWrite')
$mbr = New-Object byte[] 512
[void]$f.Read($mbr, 0, 512)
$offset = [BitConverter]::ToUInt32($mbr, 446 + 8) * 512L
[void]$f.Seek($offset, 'Begin')
$f.Write($image, 0, $image.Length)
$f.Close()

diskpart /s $attach | Out-Null
try {
    $disk = (Get-DiskImage -ImagePath $vhd).Number
    $part = (Get-Partition -DiskNumber $disk | Select-Object -First 1).PartitionNumber
    & $Exe mount "${disk}:${part}" 'J:' --rw
    if ($LASTEXITCODE) { throw 'mount of the raw partition failed' }
    Check 'raw partition serves files' ((Get-Content 'J:\hello.txt') -eq 'hello from linux')
    Set-Content 'J:\raw.txt' 'written through the raw device'
    New-Item -ItemType Directory 'J:\rawdir' | Out-Null
    Copy-Item "$env:WINDIR\notepad.exe" 'J:\rawdir\copy.exe'
    Check 'raw partition copy is byte-exact' ((Get-FileHash "$env:WINDIR\notepad.exe").Hash -eq (Get-FileHash 'J:\rawdir\copy.exe').Hash)
    Check 'a locked read-write mount stays listed' ((& $Exe list | Out-String) -match "${disk}:${part}")
    & $Exe unmount 'J:'
    if ($LASTEXITCODE) { throw 'unmount of the raw partition failed' }

    # Hotplug: a remembered volume mounts itself on arrival, and unplugging frees the letter.
    & $Exe automount on "${disk}:${part}" 'J:'
    if ($LASTEXITCODE) { throw 'could not enable automount' }
    diskpart /s $detach | Out-Null
    diskpart /s $attach | Out-Null
    Check 'a remembered volume mounts itself when plugged in' (Wait-For { Test-Path 'J:\hello.txt' })
    diskpart /s $detach | Out-Null
    Check 'unplugging a mounted volume frees its drive letter' (Wait-For { -not (Test-Path 'J:\') })
    diskpart /s $attach | Out-Null
    [void](Wait-For { Test-Path 'J:\hello.txt' })
    $disk = (Get-DiskImage -ImagePath $vhd).Number
    & $Exe unmount 'J:'
    & $Exe automount off "${disk}:${part}"
    if ($LASTEXITCODE) { throw 'could not disable automount' }
} finally {
    diskpart /s $detach | Out-Null
}

# Hand the partition's contents to the Linux job.
$f = [IO.File]::OpenRead($vhd)
[void]$f.Seek($offset, 'Begin')
$back = New-Object byte[] $image.Length
[void]$f.Read($back, 0, $back.Length)
$f.Close()
[IO.File]::WriteAllBytes((Join-Path (Resolve-Path $Out).Path 'ext4-raw.img'), $back)
Remove-Item $vhd, $create, $attach, $detach

& $Exe service uninstall
'All end-to-end checks passed.'
