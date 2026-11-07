# End-to-end on a real Windows machine with no WinFsp installed: the one-step setup, the real
# service and driver, drive letters, raw partitions and hotplug, then a full uninstall. The
# images it leaves behind go to the Linux job, where e2fsck and btrfs check judge them.
param([string]$Exe, [string]$Out)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force $Out | Out-Null
$Out = (Resolve-Path $Out).Path
$driver = "${env:ProgramFiles(x86)}\WinFsp\bin\winfsp-x64.dll"
$program = "$env:ProgramFiles\Causeway"
$arp = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Causeway'
$link = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Causeway.lnk"

# The program is a GUI executable: PowerShell only waits for it when its output is piped.
function Causeway {
    & $Exe @args | Out-Host
    if ($LASTEXITCODE) { throw "causeway $args failed with $LASTEXITCODE" }
}

function Expand-Fixture($name) {
    $src = [IO.File]::OpenRead("tests/fixtures/$name.img.gz")
    $gz = New-Object IO.Compression.GZipStream($src, [IO.Compression.CompressionMode]::Decompress)
    $dst = [IO.File]::Create("$Out/$name.img")
    $gz.CopyTo($dst)
    $dst.Close(); $gz.Close(); $src.Close()
    "$Out\$name.img"
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

Check 'the machine starts without the driver' (-not (Test-Path $driver))
Causeway install
Check 'setup installed the bundled driver' (Test-Path $driver)
Check 'setup started the service' ((Get-Service Causeway).Status -eq 'Running')
Check 'setup installed to Program Files' (Test-Path "$program\causeway.exe")
Check 'setup added a Start menu entry' (Test-Path $link)
Check 'setup is listed in installed apps' (Test-Path $arp)
Causeway install
Check 'running setup again keeps the service running' ((Get-Service Causeway).Status -eq 'Running')

foreach ($item in @(@('ext4-default', 'K'), @('btrfs-default', 'L'))) {
    $name, $d = $item
    $img = Expand-Fixture $name
    Causeway mount $img "${d}:" --rw
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

    Causeway scrub "${d}:"
    Causeway unmount "${d}:"
    Check "$name drive letter is gone" (-not (Test-Path $root))
}

# Read-only mounts must not change a single byte.
$img = Expand-Fixture 'ext3-1k'
$before = (Get-FileHash $img).Hash
Causeway mount $img 'M:'
Check 'read-only mount serves files' ((Get-Content 'M:\hello.txt') -eq 'hello from linux')
$blocked = $false
try { Set-Content 'M:\nope.txt' 'x' -ErrorAction Stop } catch { $blocked = $true }
Check 'read-only mount refuses writes' $blocked
Causeway unmount 'M:'
Check 'read-only mount left the image untouched' ($before -eq (Get-FileHash $img).Hash)

# Raw partition access, the real-disk path, on a virtual disk so nothing real is touched.
# A fixed VHD is a plain disk image, so the filesystem can be placed with ordinary file I/O.
$vhd = "$Out\disk.vhd"
$create = "$Out\create.txt"
# A run that stopped early can leave its disk behind.
if (Test-Path $vhd) {
    Dismount-DiskImage -ImagePath $vhd -ErrorAction SilentlyContinue | Out-Null
    Remove-Item $vhd
}
"create vdisk file=`"$vhd`" maximum=64 type=fixed`nselect vdisk file=`"$vhd`"`nattach vdisk`nconvert mbr`ncreate partition primary id=83`ndetach vdisk" |
    Set-Content $create -Encoding ascii
diskpart /s $create | Out-Null
if ($LASTEXITCODE) { throw 'could not create the virtual disk' }

$fixture = Expand-Fixture 'ext4-1k-nocsum'
$image = [IO.File]::ReadAllBytes($fixture)
Remove-Item $fixture
$f = [IO.File]::Open($vhd, 'Open', 'ReadWrite')
$mbr = New-Object byte[] 512
[void]$f.Read($mbr, 0, 512)
$offset = [BitConverter]::ToUInt32($mbr, 446 + 8) * 512L
[void]$f.Seek($offset, 'Begin')
$f.Write($image, 0, $image.Length)
$f.Close()

Mount-DiskImage -ImagePath $vhd -NoDriveLetter | Out-Null
try {
    $disk = (Get-DiskImage -ImagePath $vhd).Number
    $part = (Get-Partition -DiskNumber $disk | Select-Object -First 1).PartitionNumber
    Causeway mount "${disk}:${part}" 'J:' --rw
    Check 'raw partition serves files' ((Get-Content 'J:\hello.txt') -eq 'hello from linux')
    Set-Content 'J:\raw.txt' 'written through the raw device'
    New-Item -ItemType Directory 'J:\rawdir' | Out-Null
    Copy-Item "$env:WINDIR\notepad.exe" 'J:\rawdir\copy.exe'
    Check 'raw partition copy is byte-exact' ((Get-FileHash "$env:WINDIR\notepad.exe").Hash -eq (Get-FileHash 'J:\rawdir\copy.exe').Hash)
    Check 'a locked read-write mount stays listed' ((& $Exe list | Out-String) -match "${disk}:${part}")
    Causeway unmount 'J:'

    # Hotplug: a remembered volume mounts itself on arrival, and unplugging frees the letter.
    Causeway automount on "${disk}:${part}" 'J:'
    Dismount-DiskImage -ImagePath $vhd | Out-Null
    Mount-DiskImage -ImagePath $vhd -NoDriveLetter | Out-Null
    Check 'a remembered volume mounts itself when plugged in' (Wait-For { Test-Path 'J:\hello.txt' })
    Dismount-DiskImage -ImagePath $vhd | Out-Null
    Check 'unplugging a mounted volume frees its drive letter' (Wait-For { -not (Test-Path 'J:\') })
    Mount-DiskImage -ImagePath $vhd -NoDriveLetter | Out-Null
    [void](Wait-For { Test-Path 'J:\hello.txt' })
    $disk = (Get-DiskImage -ImagePath $vhd).Number
    Causeway unmount 'J:'
    Causeway automount off "${disk}:${part}"
} finally {
    Dismount-DiskImage -ImagePath $vhd | Out-Null
}

# Hand the partition's contents to the Linux job.
$f = [IO.File]::OpenRead($vhd)
[void]$f.Seek($offset, 'Begin')
$back = New-Object byte[] $image.Length
[void]$f.Read($back, 0, $back.Length)
$f.Close()
[IO.File]::WriteAllBytes("$Out\ext4-raw.img", $back)
Remove-Item $vhd, $create

# Uninstalling reverses all of it, including the driver setup brought.
Causeway uninstall
Check 'uninstall removed the service' (-not (Get-Service Causeway -ErrorAction SilentlyContinue))
Check 'uninstall removed the bundled driver' (-not (Test-Path $driver))
Check 'uninstall removed the program' (-not (Test-Path $program))
Check 'uninstall removed the Start menu entry' (-not (Test-Path $link))
Check 'uninstall removed the installed apps entry' (-not (Test-Path $arp))
'All end-to-end checks passed.'
