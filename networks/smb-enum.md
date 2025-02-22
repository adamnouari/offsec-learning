# SMB Enumeration


## NetBIOS

Session-layer protocol that allows computers on a local network to communicate with each other.

NetBIOS:
- Port 139
- Services for naming, session management and datagram distribution across LAN
- Allows devices connected to network to identify each other, resolve names to IP addresses and establish network communication sessions

SMB
- Port 445
- Primarily used for sharing files, printers and other resources beteween computers.

SMB was formerly designed to operate over NetBIOS. Newer SMB protocol implementations do not need this and communicate directly over TCP/IP. They usually however still support communication over NetBIOS for backwards compatibility.


## Enumeration

### Nmap

Scan nmap against ports 139/445/both to identify possible SMB service. Can then use NSE to enumerate further info such as users, shares, OS discovery etc.

### nbtscan

`nbtscan` is a tool which discovers more information about the NetBIOS information

Run like this:

```
sudo nbtscan [-r] <IP_range>
```
`-r` flag is optional, it just does reverse DNS to possibly find provide info in reporting


### net view

Found within Windows environments, enumerates SMB shares:
```
net stat \\<target_hostname> /all
```
`/all` will list all shares. Those with a `$` at the end are marked as admin shares. :eyes: