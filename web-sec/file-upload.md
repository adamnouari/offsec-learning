# File Upload


## Description

Self-explanatory; just fuck about until a possibly malicious script seems to be accepted.


## Filter Bypass Techniques

- Changing the content-type e.g. from `application/x-php` to `application/x-www-form-url-encoded` or `image.jpeg`
- Directory traversal techniques to see if file can be uploaded to executable directory
- Alternate file extensions (e.g. `.php` --> `.php3` or `.shtml`)
- Obfuscated file extensions e.g.:
    - `.pHp`,
    - `.php.jpg` if different parsing behaviour for validation vs runtime
    - `.p.phphp` for string match skipping
    - `%2Ephhp` encoding special chars like . or / in case parsing behaviour is vulnerable
    - `.php%00.jpg` or `.php;.jpg` for low-level parsing behaivour exploit
    - Encoding using URL or multibyte (e.g. UTF) and hope server parses it differently (e.g. ignoring URL or only using smallest byte of UTF if file handling methods use single-byte charsets like ASCII)
- Changing method e.g. to GET or PUT
- Changing file magic bytes
- Exploiting race conditions on file upload requests
