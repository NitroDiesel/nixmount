# Installs the last release, gives it a remembered read-write mount, then installs the new
# build over it while that mount is open. Settings, the mount and the files must come through.
param([string]$Old, [string]$New, [string]$Out)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force $Out | Out-Null
$Out = (Resolve-Path $Out).Path
$version = (Select-String -Path Cargo.toml -Pattern '^version = "(.+)"').Matches[0].Groups[1].Value
$arp = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NixMount'
$settings = "$env:ProgramData\NixMount\config.json"

# The program is a GUI executable: PowerShell only waits for it when its output is piped.
function Run($exe) {
    $ErrorActionPreference = 'Continue'
    & $exe @args 2>&1 | Out-Host
    if ($LASTEXITCODE) { throw "$exe $args failed with $LASTEXITCODE" }
}

function Wait-For($condition) {
    for ($i = 0; $i -lt 30; $i++) {
        if (& $condition) { return $true }
        Start-Sleep -Seconds 1
    }
    $false
}

$failed = 0
function Check($what, $ok) {
    if ($ok) { "ok: $what" } else { $script:failed++; "FAILED: $what" }
}

$src = [IO.File]::OpenRead('tests/fixtures/ext4-1k-nocsum.img.gz')
$gz = New-Object IO.Compression.GZipStream($src, [IO.Compression.CompressionMode]::Decompress)
$image = "$Out\upgrade.img"
$dst = [IO.File]::Create($image)
$gz.CopyTo($dst)
$dst.Close(); $gz.Close(); $src.Close()

try {
    Run $Old install
    "upgrading from " + (Get-ItemProperty $arp).DisplayVersion + " to $version"
    Run $Old automount on $image 'J:' --rw
    Run $Old mount $image 'J:' --rw
    Check 'the last release serves the image' (Wait-For { Test-Path 'J:\hello.txt' })
    Set-Content 'J:\before-upgrade.txt' 'written before the upgrade'
    $before = Get-Content $settings -Raw

    Run $New install
    Check "the installed version is now $version" ((Get-ItemProperty $arp).DisplayVersion -eq $version)
    Check 'settings came through unchanged' ($before -eq (Get-Content $settings -Raw))
    Check 'the service is running' ((Get-Service NixMount).Status -eq 'Running')
    Check 'the installed program is the new one' ((Get-FileHash "$env:ProgramFiles\NixMount\nixmount.exe").Hash -eq (Get-FileHash $New).Hash)
    Check 'the remembered volume came back by itself' (Wait-For { Test-Path 'J:\hello.txt' })
    Check 'a file written before the upgrade survived it' ((Get-Content 'J:\before-upgrade.txt') -eq 'written before the upgrade')
    Set-Content 'J:\after-upgrade.txt' 'written by the new version'
    Check 'the new version can write' ((Get-Content 'J:\after-upgrade.txt') -eq 'written by the new version')
    Run $New unmount 'J:'
    Run $New automount off $image
} finally {
    $ErrorActionPreference = 'Continue'
    & $New uninstall 2>&1 | Out-Host
}
Check 'uninstall removed the program' (-not (Test-Path "$env:ProgramFiles\NixMount"))
Check 'uninstall removed the driver' (-not (Test-Path "${env:ProgramFiles(x86)}\WinFsp\bin\winfsp-x64.dll"))
if ($failed) { throw "$failed checks failed" }
