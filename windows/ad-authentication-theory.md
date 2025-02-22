# Active Directory Authentication


Examples where a user wants to access a service using Active Directory authentication.

## NTLM

1. CLIENT computed NTLM hash from user's password
2. CLIENT sends username to APPLICATION SERVER
3. APPLICATION SERVER returns nonce to CLIENT (challenge)
4. CLIENT encrypts nonce using NTLM hash from user's password and sends to APPLICATION SERVER (response)
5. APPLICATION SERVER sends client response (encrypted nonce), username and nonce to DOMAIN CONTROLLER
6. DOMAIN CONTROLLER encrypts nonce with NTLM hash of user and compares to client's response
7. DOMAIN CONTROLLER approves authentication to APPLICATION SERVER if successful


## Kerberos

Key Distribution Center (KDC) role is assumed by Domain Controller.

1. CLIENT initiates Authentication Server Request (AS-REQ) to KDC.
    - AS-REQ is an contains:
        - Username
        - Encrypted timestamp using a hash derived from the password of the user

2. KDC looks up user's password hash in `ntds.dit` file and attempts to decrypt timestamp. If decryption is successful **and** timestamp is not a duplicate, then approve authentication with step #3.

3. KDC returns Authentication Server Reply (AS-REP) to CLIENT.
    - AS-REP contains:
        - Session Key A (derived from user password hash)
        - TGT (encrypted using krbtgt NTLM account hash known only to KDC)
            - User data
            - Domain data
            - Requesting IP
            - Timestamp
            - Session Key A

4. CLIENT makes Ticket Granting Service request (TGS-REQ) to KDC's Ticket Granting Service
    - TGS-REQ contains:
        - Username (encrypted with Session Key A)
        - Timestamp (encrypted with Session Key A)
        - Name of APPLICATION SERVER resource access is requested to
        - Encrypted TGT (with krbtgt NTLM hash)

5. KDC TGS checks if resource exists and if so, decrypts TGT using krbtgt NTLM hash, extract Session Key A from TGT and uses Session Key A to decrypt the username and timestamp.

6. KDC TGS checks if timestamp is valid, if username of TGS-REQ is same username in TGT, if requesting client IP matches IP in TGT etc.

7. If #6 is successful, KDC TGS returns TGS-REP to CLIENT.
    - TGS-REP contains:
        - Name of service which access has been granted (encrypted with Session Key A)
        - Session Key B to be used with APPLICATION SERVER (encrypted with Session Key A)
        - Service Ticket containing username, group memberships and Session Key B (encrypted using a password hash of the service account of the service)

8. CLIENT send Application Request (AP-REQ) to APPLICATION SERVER.
    - AP-REQ contains:
        - Username (encrypted with Session Key B)
        - Timestamp (encrypted with Session Key B)
        - Service Ticket

9. APPLICATION SERVER decrypts Service Ticket using a password hash of its service account. Extract Session Key B from Service Ticket. User Session Key B to decrypt username and timestamp.

10. APPLICATION SERVER validates timestamp, AP-REQ username vs Service Ticket username and examines groups for access control.

11. APPLICATION SERVER grants access