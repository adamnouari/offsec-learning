# JWT Attacks

## Enumeration

### Finding the Public Key

Try `/jwks.json` or `/.well-known/jwks.json` or other common JKUs.

Try also to crack public RSA keys from 2 or more JWT signatures. Can be done using tools such as rsa_sign2n (https://github.com/silentsignal/rsa_sign2n).

## Methodology

Try the following:

1. Analyse headers and claims (payload) to look for interesting info
2. Is the signature being verified properly? No sig/invalid but present sig
3. Can you supply an unsecured JWT by chaing the `alg` arg to `none` (may require obfuscation)
4. Can you brute force a weak key?
5. Supply your own JWK?
6. Supply your own JKU?
7. Does `kid` point to a file? Can you point to a diff file via directory traversal and use this as a key? (find a file with deterministic contents)
8. Change `alg` to use a symmetric algorithm from asymmetric. To do this:
    1. Get server public key
    2. Convert key to correct format (must use IDENTICAL format server uses, either JWK or PEM/X.509 etc.); might need to play around with various formatting
    3. Craft evil JWT
    4. Sign using key and symmetric algorithm
