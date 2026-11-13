#Requires -Version 5.1
<#
NetworkRadar 8.4.0 launcher
- Runs the Python intelligence platform from this installation directory.
- Does not require elevation; capture permissions may be needed for TShark.
- Passes command-line options through to networkradar.py.
#>
Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$App = Join-Path $Root "networkradar.py"
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"

if (-not (Test-Path -LiteralPath $App -PathType Leaf)) {
    Write-Error "NetworkRadar application not found: $App"
    exit 2
}

$Python = Get-Command "python" -ErrorAction SilentlyContinue
$PyLauncher = Get-Command "py" -ErrorAction SilentlyContinue

Push-Location $Root
try {
    if ($Python) {
        & $Python.Source -u $App @args
        $Code = $LASTEXITCODE
    }
    elseif ($PyLauncher) {
        & $PyLauncher.Source -3 -u $App @args
        $Code = $LASTEXITCODE
    }
    else {
        Write-Host "Python 3 was not found. Install Python 3.10+ and retry." -ForegroundColor Red
        exit 2
    }
}
finally {
    Pop-Location
}
if ($null -eq $Code) { $Code = 1 }
exit $Code
