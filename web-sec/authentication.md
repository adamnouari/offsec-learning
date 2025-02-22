# Authentication

## Poor vs Broken Authentication

Poor authentication methods are when the authentication mechanisms provide the barebones of authentication but are poorly implemented, meaning they can be exploited and bypassed. Think along lines of:
1. Username enumeration
2. Input bypass
3. Lack of brute-force protecition
4. Vulnerability in third-party authentication mechanisms (such as SSO implementation)

Broken authentication on the other hand usually stems from broken business logic, BAC or other form of misconfiguration of identity and access.


## Username Enumerations

Try likely usernames. Analyse application/service behaviour. Need to consider:
- Status codes from HTTP responses
- Error messages
- Response times
- Response lengths
- Any other varying behaviour


## Authentication Bypass 

### Brute-force Defenses
Try to understand and bypass defense rules e.g. if app initiates login lockout for too many failed login attempts at the account level, limit attempts per account and rotate through accounts before lockout. Similarly, lockout is based around the IP level, try a sucessful known login and see if this resets the failed login timeout count per requestor IP, or try spoofing a requestor IP if possible. Can then automate by including the valid credentials at small enough intervals in wordlists.

Another example, if user rate limiting is applied (typically at IP level), look into possible bypasses:
- Can the requesting IP be faked?
- Can multiple credentials be evaluated at once?
- Can delays be deliberately introduced between requests to avoid time-based rate limiting? (Need to ensure this doesn't take too long to brute-force if so!)

### Implementation Checks
Is the application actually evaluating all the data you're sending properly? If there's lots of inputs being evaluated, it could be only a subset are used for authentication and the others are not validated.

Can pages be skipped in MFA or multi-layered authentication implementations?

Can information be swapped or other logic be exploited during MFA or multi-layered implementations?

How strong are authentication token generation mechanisms? Can these be enumerated and/or brute-forced?

### Authentication Management
This relates to other attacks such as 
- Session management
- Authentication tokens (e.g. JWT, OAuth 2.0 etc.)
- Lack of encryption of authentication data etc.
- Offline password cracking potential
- Access to sensitive account actions e.g. resetting passwords, exfiltrating account data etc.


## Things to keep in mind

1. Authentication might not be directly vulnerable itself, but could be the foundation for other attack vectors such as session token management exploits and insecure deserialisation
2. Analyse patterns in credentials e.g. usernames following a set syntactic format, passwords being of minimum length etc. to better customise attacks to system in question
3. Check if the website, for whatever reason, is using basic HTTP authentication in headers. Lucky day if so.
