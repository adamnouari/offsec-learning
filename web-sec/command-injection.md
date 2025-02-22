# OS Command Injection


## Operators and Techniques

Kinda rare vulnerability...

Need to find how to escape current command, might involve directly injecting character below OR first escaping any strings/other things the command might be currently executed in, e.g. using quote at the start of the injection to escape strings.

Operators for both Windows/UNIX:
- `&` and `&&`
- `|` and `||`

UNIX only:
- `;`
- `\n` or `0x0a` - new line
- Using backticks \`{COMMAND}\` or dollar sign `$({COMMAND})` to 


## Blind Injection

In most cases the injection results in blind actions where output is not directly returned. Therefore, try:  

Have you tried...
1. Checking for time delays? Use a command that takes a while to process e.g. `ping -c 15 localhost`
2. Saving output to an accessible location e.g. `whoami > /path/to/static/files/output.txt`
3. Out-of-band communications via DNS lookup or `curl`ing a server under your control. If so, can you exfiltrate data?
