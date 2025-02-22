# Path / Directory Traversal

## Identification

- Hover over all buttons
- Check all links
- Navigate to all accessible pages
- Examinee page's source code

## Bypassing Restrictions

Things to try:
1. Absolute file paths rather than relative.
2. Are traversal sequences being stripped? If so:
    1. Check for non-recursive stripping, i.e. using `....//` which after stripping non-recursively becomes `../`
    2. Obfuscation, via URL or other encoding
3. Using correct start path and then traversing: `path/to/intended/dir/../../../secret/stuff`
4. Are specific file extensions expted? Similar to file upload, try null bytes `&00` before ext: `../../secret/stuff%00.jpg`
5. Remember, Windows-hosted servers will interpret `\` like it's `/`, so always worth a try