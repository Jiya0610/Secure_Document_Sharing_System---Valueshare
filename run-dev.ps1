$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$backend = Join-Path $root 'backend'
$frontend = Join-Path $root 'frontend'
$rootPython = Join-Path $root '.venv\Scripts\python.exe'
$backendPython = Join-Path $backend '.venv\Scripts\python.exe'
$python = if (Test-Path -LiteralPath $rootPython) { $rootPython } elseif (Test-Path -LiteralPath $backendPython) { $backendPython } else { throw "Python environment not found. Create one with: py -m venv backend\.venv" }
if (-not (Test-Path -LiteralPath (Join-Path $backend '.env'))) {
    throw "Backend configuration not found. Create $backend\.env from .env.example and set FILE_ENCRYPTION_KEY."
}

$listeners = Get-NetTCPConnection -LocalPort 5000 -State Listen -ErrorAction SilentlyContinue
$processIds = $listeners | Select-Object -ExpandProperty OwningProcess -Unique
foreach ($processId in $processIds) {
    $process = Get-CimInstance Win32_Process -Filter "ProcessId = $processId"
    $exe = if ($process.ExecutablePath) { [IO.Path]::GetFullPath($process.ExecutablePath) } else { '' }
    $isProjectPython = $exe -and ($exe -ieq [IO.Path]::GetFullPath($rootPython) -or $exe -ieq [IO.Path]::GetFullPath($backendPython))
    $isPythonApp = $process.Name -match '^pythonw?\.exe$' -and $process.CommandLine -match '(?i)\bapp\.py\b'
    if ($isProjectPython -or $isPythonApp) {
        Write-Host "Stopping the previous Flask server (PID $processId)."
        Stop-Process -Id $processId -Force
    } else {
        throw "Port 5000 is being used by $($process.Name) (PID $processId), not a Python app.py server. Close that program, then run this script again."
    }
}
Start-Sleep -Milliseconds 500
$backendCommand = "Set-Location -LiteralPath '$backend'; & '$python' app.py"
Start-Process -FilePath 'powershell.exe' -WorkingDirectory $backend -ArgumentList @('-NoExit', '-Command', $backendCommand)
Start-Process -FilePath 'powershell.exe' -WorkingDirectory $frontend -ArgumentList @('-NoExit', '-Command', 'npm run dev')
Write-Host 'Restarted the project backend and started the Vite frontend in separate PowerShell windows.'
Write-Host 'Keep both windows open. Open the Local URL shown by Vite.'


