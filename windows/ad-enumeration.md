# Active Directory Enumeration

## Theory

LDAP is used as the querying channel for Active Directory.

LDAP path structure: `LDAP://HostName[:Port][/DistinguishedName]`
- *HostName* - can be IP or domain, but in case of multiple DCs on a network, you may want to explicitly write the IP.
- *DistinguishedName* - uniquely identifies an object in AD, including the domain itself, e.g.:
    - `CN=Stefano,CN=Users,DC=example,DC=com` = com.example.Users.Stefano
        - CN = Common Name (specifies identifiers for the object)
        - DC = Domain Component (represents the top of an LDAP tree)

Example manual PowerShell script performing LDAP querying of Active Directory objects:

```
# Use this script by importing the module LDAPSearch and run the script and assign to a variable to query the results of e.g. via .properties

function LDAPSearch {
        # Get query from commandline e.g. LDAPSearch -LDAPQuery "(samAccountType=805306368)" or "(&(objectCategory=group)(cn=Some Name*))"
        # This weird number is decimal for 0x30000000 which means "User" for SAM account type
        param ( [string]$LDAPQuery )

        # Get primary domain controller hostname
        $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name

        # Get LDAP distinguished name using built-in Active Directory Services Interface
        $DN = ([adsi]'').distinguishedName

        # Build LDAP path
        $LDAPPath = "LDAP://$PDC/$DN"

        # Get LDAP tree as Directory Entry object, starting from the top level of the domain
        $DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry($LDAPPath)

        # Search directory
        $DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher($DirectoryEntry, $LDAPQuery)

        return $DirectorySearcher.FindAll()

}
```


## Enumeration with cmd.exe tools

- `net user /domain`
- `net user <USER> /domain`
- `net group /domain`
- `net group "<GROUP_NAME>" /domain`
- `setspn -L [<SERVICENAME>]` - get all SPNs or specific service's SPNs
- `wmic /node:localhost path win32_computersystem get username` - get logged in users, change `localhost` to target hostname


## Enumeration with PowerView

PowerView: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1 (raw b like https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/refs/heads/master/Recon/PowerView.ps1)
- see also the docs: https://powersploit.readthedocs.io/en/latest/Recon/

COMMANDS

- `Get-NetDomain`
- `Get-DomainPolicy`
- `Get-NetUser [| Select cn,<PROPERTY>,...]` // cn = common name
    - Possible fields of interest include `cn`, `badpwdcount`, `pwdlastset`, `lastlogon`, `useraccountcontrol`
    - `Get-NetUser -SPN [| Select samaccountname,serviceprincipalname]` - get SPNs
        - SPNs are unique service identifiers associating a service with a specific service account in AD for more complex services. Simple services run as `LocalSystem`, `LocalService` or `NetworkService`
- `Get-NetGroup "<GROUP_NAME>" [| Select member]`
    - Possible fields of interest include `cn`, `member`, `memberof`, `grouptype`, `distinguishedname` 
- `Get-NetComputer`
    - Possible fields of interest include `cn`, `logoncount`, `serviceprincipalname`, `distinguishedname` , `operatingsystem`, `operatingsystemversion`, `dnshostname`
- `Find-LocalAdminAccess`
    - find out if this user has local admin rights on other machines on the network. Relies on the "OpenServiceW" function which connects to the SCM on the target machines. Attempting this requires admin privileges on the target for the access right `SC_MANAGER_ALL_ACCESS`.
    - SCM = Service Control Manager = database of installed services and drivers on a Windows computer.
- `Get-NetSession -ComputerName <HOSTNAME> [-Verbose]` - gets logged on user sessions on a target --> may not work with newer Windows builds.
- `Get-ObjectAcl -Identity <OBJ_NAME> [| Select SecurityIdentifier,ActiveDirectoryRights | Where-Object {$_.ActiveDirectoryRights -eq '<PERMISSION>'}]`
    - Returns SID of object on ACE and what AD rights it was assigned to this object. 
- `Convert-SidToName <SID>`
    - ... or for multiple SIDs, try `echo <SID1>,<SID2>,<SID3>,... | Convert-SidToName`
- `Find-DomainShare -Verbose`

https://book.hacktricks.xyz/windows-hardening/basic-powershell-for-pentesters/powerview

## AD Object Permissions

Some key possibly vulnerable permissions to pay attention to:
- `GenericAll` - Full permissions on obj
- `GenericWrite` - Edit certain attributes on obj
- `WriteOwner` - Change ownership of obj
- `WriteDACL` - Edit Access Control Entry (ACE) applied to obj
- `AllExtendedRights` - Change or reset password and other similar stuff
- `ForceChangePassword` - Change password for an obj
- `Self (Self-Membership)` - Add ourselves as e.g. member of a group


## Enumeration with SysinternalsSuite

- `PsLoggedon.exe \\<HOSTNAME>`


## Enumeration with crackmapexec

List shares:

```
link@kali:~$ crackmapexec smb <TARGET_IP> -u <USERNAME> -p "<PASSWORD>" --shares
```


## Enumeration with BloodHound

### SharpHound

SharpHound.ps1: https://github.com/BloodHoundAD/SharpHound/releases

Download the PowerShell module, download to target and import it.

COMMANDS:

`Get-Help Invoke-BloodHound`

Example basic command:
```
PS C:\> Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Temp\Path\ -OutputPrefix "PENTEST-NAME-WHATEVER"
```

### BloodHound

To analyse in BloodHound, transfer the SharpHound ZIP back to attacker machine.

To start BloodHound, need to start Neo4j NoSQL graph database:

```
link@kali:~$ sudo neo4j start
```

Navigate to server from output and login (default creds are *neo4j* and *neo4j*).

Then run `bloodhound` in terminal.

Unzip the ZIP and upload it to BloodHound for visualisation.

QUERIES:
- Get machines: `MATCH (m:Computer) RETURN m`
- Get users: `MATCH (m:User) RETURN m`
- Get logon sessions: `MATCH p = (c:Computer)-[:HasSession]->(m:User) RETURN p`



https://github.com/BloodHoundAD/BloodHound
https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/bloodhound