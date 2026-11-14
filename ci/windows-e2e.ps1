# End-to-end on a real Windows machine with no WinFsp installed: the one-step setup, the real
# service and driver, drive letters, raw partitions and hotplug, then a full uninstall. The
# images it leaves behind go to the Linux job, where e2fsck and btrfs check judge them.
param([string]$Exe, [string]$Out)
$ErrorActionPreference = 'Stop'
trap {
    "TRAPPED: $_"
    $_.InvocationInfo.PositionMessage
    exit 1
}
New-Item -ItemType Directory -Force $Out | Out-Null
$Out = (Resolve-Path $Out).Path
$driver = "${env:ProgramFiles(x86)}\WinFsp\bin\winfsp-x64.dll"
$program = "$env:ProgramFiles\NixMount"
$arp = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NixMount'
$link = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\NixMount.lnk"

# The program is a GUI executable: PowerShell only waits for it when its output is piped.
function NixMount {
    $ErrorActionPreference = 'Continue'
    & $Exe @args 2>&1 | Out-Host
    "  exit code $LASTEXITCODE from: $args" | Out-Host
    if ($LASTEXITCODE) { throw "nixmount $args failed with $LASTEXITCODE" }
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

# Any user can create the settings folder before setup runs, so nothing in it can be trusted:
# not its settings or its permissions, and not a junction aimed at something worth damaging.
$settings = "$env:ProgramData\NixMount"
$decoy = "$Out\decoy"
New-Item -ItemType Directory -Force $settings, $decoy | Out-Null
Set-Content "$settings\config.json" '{"automounts":[],"images":["C:\\planted.img"]}'
Set-Content "$decoy\private.txt" 'private'
icacls "$decoy\private.txt" /inheritance:r /grant '*S-1-5-18:F' '*S-1-5-32-544:F' '*S-1-5-19:R' | Out-Null
New-Item -ItemType Junction -Path "$settings\inner" -Target $decoy | Out-Null
icacls $settings /grant '*S-1-5-32-545:(OI)(CI)F' | Out-Null
$private = (Get-Acl "$decoy\private.txt").Sddl

NixMount install
Check 'setup clears out a settings folder planted before it ran' (@(Get-ChildItem $settings -Force).Count -eq 0)
Check 'setup leaves what a planted junction points at alone' ((Test-Path "$decoy\private.txt") -and (Get-Acl "$decoy\private.txt").Sddl -eq $private)
Check 'ordinary users cannot change the settings' (-not ((icacls $settings | Out-String) -match 'Users'))
Remove-Item -Recurse $decoy
Check 'setup installed the bundled driver' (Test-Path $driver)
Check 'setup started the service' ((Get-Service NixMount).Status -eq 'Running')
Check 'setup installed to Program Files' (Test-Path "$program\nixmount.exe")
Check 'setup added a Start menu entry' (Test-Path $link)
Check 'setup is listed in installed apps' (Test-Path $arp)
NixMount install
Check 'running setup again keeps the service running' ((Get-Service NixMount).Status -eq 'Running')

foreach ($item in @(@('ext4-default', 'K'), @('btrfs-default', 'L'))) {
    $name, $d = $item
    $img = Expand-Fixture $name
    NixMount mount $img "${d}:" --rw
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

    NixMount scrub "${d}:"
    NixMount unmount "${d}:"
    Check "$name drive letter is gone" (-not (Test-Path $root))
}

# Read-only mounts must not change a single byte.
$img = Expand-Fixture 'ext3-1k'
$before = (Get-FileHash $img).Hash
NixMount mount $img 'M:'
Check 'read-only mount serves files' ((Get-Content 'M:\hello.txt') -eq 'hello from linux')
$blocked = $false
try { Set-Content 'M:\nope.txt' 'x' -ErrorAction Stop } catch { $blocked = $true }
Check 'read-only mount refuses writes' $blocked
NixMount unmount 'M:'
Check 'read-only mount left the image untouched' ($before -eq (Get-FileHash $img).Hash)

# A relative path means the caller's folder, not the service's, and an image has one writer
# however its path is spelled.
$img = Expand-Fixture 'ext4-1k-nocsum'
Push-Location $Out
try {
    NixMount mount 'ext4-1k-nocsum.img' 'M:' --rw
    Check 'a relative image path is found from where the command ran' ((Get-Content 'M:\hello.txt') -eq 'hello from linux')
    $ErrorActionPreference = 'Continue'
    $said = & $Exe mount $img.ToUpper() 'N:' --rw 2>&1 | Out-String
    $ErrorActionPreference = 'Stop'
    Check 'a second writer of one image is refused' ($LASTEXITCODE -ne 0 -and $said -match 'in use' -and -not (Test-Path 'N:\'))
    NixMount unmount 'M:'
} finally {
    Pop-Location
}

# An encrypted volume made by cryptsetup, unlocked with a passphrase piped in as a script would.
if (Test-Path 'tests/fixtures/luks2-btrfs.img.gz') {
    $img = Expand-Fixture 'luks2-btrfs'
    $ErrorActionPreference = 'Continue'
    $said = 'not the passphrase' | & $Exe mount $img 'N:' 2>&1 | Out-String
    $code = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    Check 'a wrong passphrase is refused' (($code -ne 0) -and ($said -match "doesn't unlock") -and -not (Test-Path 'N:\'))
    $ErrorActionPreference = 'Continue'
    $said = 'nixmount' | & $Exe automount on $img 2>&1 | Out-String
    $code = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    Check 'an encrypted volume is never remembered for automounting' (($code -ne 0) -and ($said -match 'never stores'))
    # Progress goes to stderr, which Windows PowerShell would otherwise treat as a failure.
    $ErrorActionPreference = 'Continue'
    'nixmount' | & $Exe mount $img 'N:' --rw 2>&1 | Out-Host
    $code = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    Check 'the right passphrase mounts it' ($code -eq 0)
    Check 'files come out decrypted' ((Get-Content 'N:\hello.txt') -eq 'hello from linux')
    Set-Content 'N:\e2e-luks.txt' 'written through LUKS'
    Copy-Item "$env:WINDIR\notepad.exe" 'N:\copy.exe'
    Check 'a copy into an encrypted volume is byte-exact' ((Get-FileHash "$env:WINDIR\notepad.exe").Hash -eq (Get-FileHash 'N:\copy.exe').Hash)
    NixMount scrub 'N:'
    NixMount unmount 'N:'
    $raw = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($img))
    Check 'nothing reaches the disk unencrypted' (-not $raw.Contains('written through LUKS') -and -not $raw.Contains('hello from linux'))
    Remove-Variable raw
}

# Raw partition access, the real-disk path, on a virtual disk so nothing real is touched.
# A fixed VHD is a plain disk image, so the filesystem can be placed with ordinary file I/O.
$vhd = "$Out\disk.vhd"
$other = "$Out\other.vhd"
$create = "$Out\create.txt"
# A run that stopped early can leave its disks behind.
foreach ($leftover in $vhd, $other) {
    if (Test-Path $leftover) {
        Dismount-DiskImage -ImagePath $leftover -ErrorAction SilentlyContinue | Out-Null
        Remove-Item $leftover
    }
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
    NixMount mount "${disk}:${part}" 'J:' --rw
    Check 'raw partition serves files' ((Get-Content 'J:\hello.txt') -eq 'hello from linux')
    Set-Content 'J:\raw.txt' 'written through the raw device'
    New-Item -ItemType Directory 'J:\rawdir' | Out-Null
    Copy-Item "$env:WINDIR\notepad.exe" 'J:\rawdir\copy.exe'
    Check 'raw partition copy is byte-exact' ((Get-FileHash "$env:WINDIR\notepad.exe").Hash -eq (Get-FileHash 'J:\rawdir\copy.exe').Hash)
    Check 'a locked read-write mount stays listed' ((& $Exe list | Out-String) -match "${disk}:${part}")
    NixMount unmount 'J:'

    # Hotplug: a remembered volume mounts itself on arrival, and unplugging frees the letter.
    NixMount automount on "${disk}:${part}" 'J:' --rw
    Dismount-DiskImage -ImagePath $vhd | Out-Null
    Mount-DiskImage -ImagePath $vhd -NoDriveLetter | Out-Null
    Check 'a remembered volume mounts itself when plugged in' (Wait-For { Test-Path 'J:\hello.txt' })
    foreach ($round in 1..3) {
        Dismount-DiskImage -ImagePath $vhd | Out-Null
        Check "unplugging frees the drive letter ($round)" (Wait-For { -not (Test-Path 'J:\') })
        Mount-DiskImage -ImagePath $vhd -NoDriveLetter | Out-Null
        Check "plugging back in mounts it again ($round)" (Wait-For { Test-Path 'J:\hello.txt' })
    }

    # Pulled and put straight back, the path returns but the mount's handle stays dead.
    Dismount-DiskImage -ImagePath $vhd | Out-Null
    Mount-DiskImage -ImagePath $vhd -NoDriveLetter | Out-Null
    Check 'a disk pulled and put straight back can be written' (Wait-For {
        try { Set-Content 'J:\replugged.txt' 'written after a fast replug'; NixMount sync; $true } catch { $false }
    })
    NixMount unmount 'J:'

    # Any arriving disk wakes the service, and one the user detached has to stay detached.
    "create vdisk file=`"$other`" maximum=8 type=fixed" | Set-Content $create -Encoding ascii
    diskpart /s $create | Out-Null
    Mount-DiskImage -ImagePath $other -NoDriveLetter | Out-Null
    Start-Sleep -Seconds 5
    Check 'another disk arriving leaves an unmounted volume alone' (-not (Test-Path 'J:\'))
    Dismount-DiskImage -ImagePath $other | Out-Null
    Remove-Item $other

    # Pulling the disk ends that: it is a fresh arrival next time.
    Dismount-DiskImage -ImagePath $vhd | Out-Null
    Start-Sleep -Seconds 4
    Mount-DiskImage -ImagePath $vhd -NoDriveLetter | Out-Null
    Check 'a dismissed volume mounts again after a real unplug' (Wait-For { Test-Path 'J:\hello.txt' })

    # An upgrade is setup run over itself, and it must keep what the user set up.
    NixMount install
    Check 'reinstalling keeps remembered volumes' (Wait-For { Test-Path 'J:\hello.txt' })
    Check 'reinstalling leaves the settings readable' ((Get-Content "$settings\config.json" -Raw) -match 'automounts')
    $disk = (Get-DiskImage -ImagePath $vhd).Number
    NixMount unmount 'J:'
    "step: automount off"
    NixMount automount off "${disk}:${part}"
    "step: automount off done"
} finally {
    Dismount-DiskImage -ImagePath $vhd | Out-Null
}

"step: reading the partition back"
# Hand the partition's contents to the Linux job.
$f = [IO.File]::OpenRead($vhd)
[void]$f.Seek($offset, 'Begin')
$back = New-Object byte[] $image.Length
[void]$f.Read($back, 0, $back.Length)
$f.Close()
[IO.File]::WriteAllBytes("$Out\ext4-raw.img", $back)
Remove-Item $vhd, $create

"step: uninstall"
# Uninstalling reverses all of it, including the driver setup brought.
NixMount uninstall
Check 'uninstall removed the service' (-not (Get-Service NixMount -ErrorAction SilentlyContinue))
Check 'uninstall removed the bundled driver' (-not (Test-Path $driver))
Check 'uninstall removed the program' (-not (Test-Path $program))
Check 'uninstall removed the Start menu entry' (-not (Test-Path $link))
Check 'uninstall removed the installed apps entry' (-not (Test-Path $arp))
'All end-to-end checks passed.'
