# Active Enumeration


## DNS

From bash:
```
host [OPTIONS] <hostname|domain>
```

Common DNS records:
- `NS` - Nameserver records: contain name of servers hosting DNS record data
- `A` - "A" record: contains IPv4 addr of `<hostname>`
- `AAAA` - Quad "A" record: contains IPv6 addr of `<hostname>`
- `MX` - Mail Exchange records: contains names of email servers for `<domain>`
- `PTR` - Pointer records: used for reverse DNS lookups (locates DNS  records associated with IP addresses)
- `CNAME` - Canonical Name records: used to create aliases for other host records
- `TXT` - Text records: contain any arbitrary data and be used for various purposes  such as domain ownership verification

Querying the DNS servers can also be used to enumerate services themselves, e.g.:
```
for $subdomain in $(cat /usr/share/SecLists/some-list.txt); do host $subdomain.example.com; done | grep -v "not found"

# OR for reverse DNS

for $ip in $(seq 200 254); do host 192.168.0.$ip; done | grep -v "not found"
```

### Tooling & Automation

**Kali**
1. DNSRecon
    - `-d` flag to specify domain
    - `-t` flag to specify type
    - `-D` flag to specify wordlist location
    ```
    dnsrecon -d example.com -t std
    dnsrecon -d example.com -D /path/to/wordlist.txt -t brt
    ```
2. DNSEnum
    - https://github.com/darkoperator/dnsrecon
    ```
    dnsenum <hostname>
    ```

**Windows**
1. `nslookup` - Not part of LOLBAS (see below) but pretty common anyway
    ```
    nslookup <hostname>
    ```


## Port Scanning

### Netcat

Netcat is not a port scanner, but if needed it can be used to port scan:
```
nc -nv -w 1 -z <IP> 100-200

-w: timeout in seconds
-z: scan mode, zero I/O and sends no data
-u: UDP scan (without this it defaults to TCP)
-nv: verbosity, can also be -nvv
100-200 is the port range to be scanned
```

Pragmatic port scan therefore be:
```
for i in $(seq 1 254); do nc -zv -w 1 172.16.50.$i <PORT>; done
// -zv - check for listening port without sending data, verbose
// -w 1 - ensure lower time-out threshold
```

### Nmap

Requires root privileges so that it can use raw sockets on a system, free of rtestrictions from constructor socket APIs

`sudo nmap -sS -sV -Pn -p- -v -O -sC <IPS> -oA nmap/initial-external-scan`

For more info, view dedicated nmap page.

### PowerShell

- Good in terms of LOLBAS
- Can use `Test-NetConnection` cmdlet in a PowerShell script to "mimic" functionality of nmap:
    ```
    Test-NetConnection -Port 445 <IP>
    ```
    - Scanning for SMB
    - Can plug into automated script:
    ```
    1..1024 | % {echo ((Net-Object Net.Sockets.TcpClient).Connect("<IP>", $_)) "TCP PORT $_ OPEN"} 2>$null
    ```
    - For loop to scan ports 1 through 1024, represented by `$_`
    - Try to create `Net.Sockets.TcpClient` object connection to port and log message if successful
    

## LOLBAS

LOLBAS = Living Off the Land: Binaries, Scripts and Libraries \[Windows\].

These are a set of resources that are usually pre-installed and trusted on Windows systems which can be abused to screw over the network :)

Very helpful when inside the network and unable to use attacker machine's enumeration techniques.

See https://lolbas-project.github.io/


## Vulnerability Scanning

### Nessus

Need to install on Kali. To start, run `sudo systemctl start nessusd.service` and navigate to https://127.0.0.1:8834

Navigation:
- Settings to configure app such as entering target info and more
    - Advanced settings to see global settings
- Scan tab
    - *Policies* are a sets of predefined configuration options for a Nessus scan. These can be saved and loaded later as *Templates*.
    - There are also some preset templates available.
    - Split into multiple areas, discovery, vulnerabilities, compliance, web application, malware scans etc.
    - Common ones on free tier will be network scans:
        - Basic Network Scan: majority of settings are predefined; recommended by Tenable
        - Adavanced Scan: template without any predefined settings; can be used for full customisation instances
        - Advanced Dynamic Scan: same as above but the plugins do not to be selected manually; leverages dynamic plugin filter instead
    - *Plugins* are programs written in Nessus Attack Scripting Language (NASL) which contain info and algos to detect vulnerabilities.
        - Organised by plugin families, which cover different use cases.
        - Use Advanced Dynamic Scan and use the rule builder tool under Dynamic Plugins on the right panel (+ configure other tabs too)

Some common scans:
- Basic Network Scan
- Credentials Patch Audit
- Advanced Dynamic Scan (scanner does the work of finding the right plugins for us, we just configure the scan)

### WordPress Scanning

WPScan (`wpscan`) is a tool that scans for vulnerabilities from the WordPress Core version, its plugins and themes from the *WordPress Vulnerabilities Database*.