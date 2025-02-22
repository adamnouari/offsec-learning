# Tooling

## Password Cracking

### Hydra
- `hydra`
- Good in general
- Can multithread to be fast

### John the Ripper
- `john`
- Let's you crack unshadowed /etc/passwd files (unshadow with `unshadow`)


## Windows Privilege Escalation

### WinPEAS
- Enumerates privilege escalation paths | https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS
    - Run and output to file due to long output

### PrivescCheck
- Alternative to WinPEAS; runs in PowerShell and hence does not require binary execution | https://github.com/itm4n/PrivescCheck
    - Might require bypassing of execution policy restrictions, achieved via:
    ```
    PS C:\> Set-ExecutionPolict Bypass -Scope process -Force
    PS C:\> . .\PrivescCheck.ps1
    PS C:\> Invoke-PrivescCheck
    ```

### WES-NG: Windows Exploit Suggester
- Python script which refers to a database to identify missing patches to elevate privileges on target system | https://github.com/bitsadmin/wesng
    - Run from attacking machine meaning no need to upload WinPEAS or other programs to target so antivirus can't detect
    - Requires `systeminfo` to be retrieved from target to attacker machine (save output of this command to file first in order to send)
    - Once that's done, run with `wes.py systeminfo.txt`