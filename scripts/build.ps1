[CmdletBinding()]
param(
    [switch]$NoBump,
    [string]$Version
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$main = Join-Path $root 'cmd\tcpdiag\main.go'
$original = [IO.File]::ReadAllText($main)

$m = [regex]::Match($original, 'const version = "(\d+)\.(\d+)\.(\d+)"')
if (-not $m.Success) {
    throw ('could not find const version = "x.y.z" in ' + $main)
}
$current = "$($m.Groups[1].Value).$($m.Groups[2].Value).$($m.Groups[3].Value)"

if ($Version) {
    if ($Version -notmatch '^\d+\.\d+\.\d+$') {
        throw "-Version must look like 1.2.3"
    }
    $next = $Version
} elseif ($NoBump) {
    $next = $current
} else {
    $next = "$($m.Groups[1].Value).$($m.Groups[2].Value).$([int]$m.Groups[3].Value + 1)"
}

$re = [regex]::new('const version = "\d+\.\d+\.\d+"')
$updated = $re.Replace($original, "const version = `"$next`"", 1)
if ($updated -ne $original) {
    [IO.File]::WriteAllText($main, $updated, (New-Object System.Text.UTF8Encoding($false)))
}

$bin = Join-Path $root 'bin'
if (-not (Test-Path -LiteralPath $bin)) {
    New-Item -ItemType Directory -Path $bin | Out-Null
}

Push-Location $root
try {
    & go build -o 'bin\tcpdiag.exe' '.\cmd\tcpdiag'
    if ($LASTEXITCODE -ne 0) {
        throw "go build failed with exit code $LASTEXITCODE"
    }
} catch {
    # A failed build must not silently advance the source version.
    [IO.File]::WriteAllText($main, $original, (New-Object System.Text.UTF8Encoding($false)))
    throw
} finally {
    Pop-Location
}

Write-Host "built bin\tcpdiag.exe as tcpdiag $next"
