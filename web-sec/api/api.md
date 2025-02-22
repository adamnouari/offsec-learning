# API Methodology


## Authorisation!!

### IDOR
Identify weak/enumeratable data, try changing it and see what happens.

### Excessive Information Disclosure
Is this giving me too much information? Is it unnecessary for the functionality? If the answer to those questions are yes, hello EID (not big or little Eid tho). Understand where else that data is being used in the API and see if you can break stuff with it. You can then report 2-for-1 vulnerabilities.

### Mass Assignment 
Fun. Enumerate as many attributes as you can about a resource, try mass assigning these attributes for POST, PUT/PATCH or DELETE (or equivalent) operations in particular.

See what changes :0

### Malformed Inputs
See if you can bypass input validation or cause unexpected behabiour.


## Authentication


## Functionality


## Injection


## GraphQL