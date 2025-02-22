# nmap

## Scan types

### Standard TCP Connect scan
- `sT`
- Standard TCP connection
- Easily detectable by IDS

### SYN scan
- `-sS` 
- Sends RST after receiving SYN/ACK from server
- Stealth scan because:
    - It bypasses (older) IDS solutions
    - Applications running on port service will usually not log half-open connection attempts
    - Faster than Standard TCP Connect scan
- Downsides:
    - Requires root permissions
    - Can crash services that are sensitive to this; must be careful if pentesting in prod

### UDP scan
- `-sU`
- Expects no response from server because of protocol's nature:
    - If no response, either UDP is open or port is filtered so marked as `open|filtered`
    - If ICMP response received (which tells client port is unreachable), marked as `closed`
    - If for some weird reason it's replying, marked as `open`
- Way slower than TCP, so usually run with `--top-ports <num_ports>` for more acceptable scan time
    - `--top-ports` are determined fro nmap and found by default at `/usr/share/nmap/nmap-services`
- Sends either:
    - Empty packet to specific port; `ICMP port unreachable` msg returned if closed
    - For common ports, (application-layer) protoccol-specific packets are sent in an attempt to get a response from the assumed application bound to the port.
- Sometimes it's worth combing UDP scanning with a TCP scan to build a more complete picture of our target: `-sU -sS`

### NULL, FIN and XMAS scan

| Type | Command Option | Description |
| ---- | -------------- | ----------- |
| NULL | `-sN` | Sends TCP with no flag bits set |
| FIN | `-sF` | Sends TCP with FIN flag bit set |
| XMAS | `-sX` | Sends TCP with SYN, FFIN and URG flag bits set |
- `closed` if RST received (similar to UDP) as closed services should respond to malformed TCP packets with RST
    - not always the case in practice, some services explicitly configured to not reply at all for any malformed packets
- `open|filtered` if no response received (similar to UDP) because malformed TCP packets should not be responded to
- Primarily used stealth in order to evade firewalls (that may be configured to reject TCP connect or SYN scans)
- Most modern IDS solutions can detect this though :/

### ICMP scan

- `-sn` (defaults to this is not on same subnet)
- `-PE`, `-PP`, `-PM`
- For ECHO, TIMESTAMP, NETMASK request types
- Sends ICMP to hosts to *ping* targets

### ARP scan

- `-PR`
- Sends ARP to hosts to *ping* targets on same subnet (`-sn`) defaults to ARP if on same subnet as target and root privileges
- Better to use if you are in the same subnet as the target machine because:
    - Faster
    - Stealthier
    - Bypass firewall restrictions on ICMP
- Use `-PR` to disable port scanning on targets


## Host Discovery

- Also known as sweep scan
- Use the `-sn` flag
- Works by sending:
    - ICMP timestamp request
    - TCP SYN to port 443
    - TCP ACK to port 80
- Sweep scanning can also be used to enumerate hosts running a service on a specific port: `nmap -p 80 <IP_range>` will scan only for hosts with a service on port 80


## Service Enumeration

### OS Fingerprinting

- Use `-O` flag
- Will attempt to guess OS based on implementation of the TCP protocol and stack, will only report confident guesses
    - May not always be accurate as firewalls/other network devices may rewrite or tamper with packets
- To see any OS guess regardless of confidence, use `--osscan-guess`


### Banner Grabbing

- Use `-A` flag
- But banners can be deliberately modified by sysadmins to mislead viewers

### Scripts

See below

## Scripts

- NSE Scripts are in `/usr/share/nmap/scripts/` directory by default
- Can use `--script-help` on a specific script to get more information about it

Just use `--help` menu

List via `ls -l <dir_to_scripts> | grep <script_search_regex>`

If you download a script `.nse` file from the internet, copy it to the scripts dir stated above and then `sudo nmap --script-updatedb` to load it into NSE.