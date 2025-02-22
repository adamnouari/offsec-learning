# SNMP Enumeration


## SNMP

Simple Network Management Protocol... is really anything but...

OID = Object ID

OIDs follow a branching structure. For example, `x.x.x.y` might correspond to a specific group of objects at layer `x.x.x` whos ID is `y`.

MIB = Management Information Base

Just a table that maps OIDs to human-readable names.

Uses UDP protocol on port 161.

SNMP v1 and v2-2c do not use encryption or authentication other than a shared "community string". These are usually guessable too, such as being just something simple like `public`, `private` or `manage`. SNMP v3 uses encyrption and user/pass creds though. If accessible, can be big for enumeration.


## Nmap

```
sudo nmap -sU --open -p161 <IP_range>
```

where `--open` limits output only to open ports.

Have a browse through NSE for something useful.

## Onesixtyone

CLI tool for SNMP service enumeration. Give it 2 files: one with list of community string guesses and other with IPs.

```
echo public > community.txt
echo private >> community.txt
echo manager >> community.txt

for ip in $(seq 1 254); do echo 192.168.50.$ip; done > ips.txt

onesixtyone -c community.txt -i ips.txt
```

## Probing SNMP

Once we've identified SNMP services, we can query the MIB for information on machines. One tool to use is `snmpwalk`

```
snmpwalk -c <community_string> -v1 -t <timeout> <IP>
```

where `-v1` specifies SNMP protocol version; `-t` specifies timeout period in secs

This gives us a shit load of information. If we add `-Oa` to the end, any hexademic strings that were previously not converted to ASCII will be forcibly converted, possibly resulting in even more info :O

When we find something interesting, we can enumerate a lot of stuff about the target machine using the following syntax and replacing `<OID>` with the OID for the desired information:
```
snmpwalk -c <community_string> -v1 -t <timeout> <IP> <OID>

1.3.6.1.4.1.77.1.2.25  = Users on machine
1.3.6.1.2.1.25.4.2.1.2 = Currently running processes on machine
1.3.6.1.2.1.25.6.3.1.2 = Installed software on the machine
1.3.6.1.2.1.6.13.1.3   = Currently listening TCP ports on machin
```

Using one or a combo of these (and other OIDs) can help us find:
- Users
- Vulnerable software
- Antivirus software
- TCP services that are only accessible to internal connections and otherwise invisible to external scanning

Yassss