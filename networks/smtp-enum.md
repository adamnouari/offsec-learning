# SMTP Enumeration


## Nmap

Use nmap against port 25 for SMTP or another port for other mailing protocols such as POP3 etc. The rest of these notes have details specific to SMTP, so for other protos just adapt the syntax/semantics.


## User Enumeration

Use the SMTP protocol's commands to find users. E.g. with the following commands, we can:
- Verify a user identity's existence using `VRFY`
- Get mailing list members using `EXPN`

Commands can be issues in various ways.

### Netcat

```
nc -nv <IP> 25
(Connection stuff)
> VRFY <username>
```

Depending on output, we can tell if `<username>` exists or not.

### Automation

We can automate this process to enumertate users using a (long) user list. E.g. in Python, we make use of the `socket` module to establish a TCP socket to port 25 of the SMTP server and send a shit load of `VRFY` commands for each user in the user list to quickly enumerate users.

### Windows Tools

For LOLBAS, we can use PowerShell `Test-NetConnection` cmdlet:

```
Test-NetConnection -Port 25 <IP>
```

This won't let us interact with the service though. We can do this via Telnet, which is not native to Windows but can be installed via `dism`:

```
dism /online /Enable-Feature /FeatureName:TelnetClient
```

It's annoying and it requires admin privileges too to install via `dism` but hey it works:

```
telnet <IP> 25
(Connection stuff)
VRFY son-goku
252 2.0.0 son-goku
VRFY uwu
550 5.1.1 <uwu>: Recipient address rejected: User unknown in local recipient table (get that weeb ass shit outta here)
```