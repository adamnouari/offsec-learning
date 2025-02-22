# XSS

## Cheatsheet

PortSwigger: https://portswigger.net/web-security/cross-site-scripting/cheat-sheet


## Database Enumeration

First and foremost need to identify database. Follow through with the rest based on idenfitified DB. Use HT/PATT/something else.


## UNION Attacks

Used to get data from other tables. E.g. `SELECT a, b FROM table1 UNION SELECT c, d FROM table2;`

Requirements:
1. Column count needs to match in each sub-query on either side of UNION
2. Each column must map to a column in the other query with the same data type. E.g. in above example, if `b` is an integer then `d` must also be an integer

### Requirement 1 - Column Enumeration

Objective: find number of columns in first sub-query to match in second UNION sub-query.

Can be achieved via `ORDER BY` clauses:
```
' ORDER BY 1;--
' ORDER BY 2;--
' ORDER BY 3;--
...
```
and examine responses. If this doesn't work, try:
```
' UNION SELECT NULL;--
' UNION SELECT NULL, NULL;--
' UNION SELECT NULL, NULL, NULL;--
...
```
or try HackTricks/PATT/something.

Send `query{__typename}` to any GraphQL endpoint and it will return the string `{"data": {"__typename": "query"}}` in response. Can be used to identify valid GraphQL endpoints.
- This is because `__typename` is a metadata field returning information about the query you are trying to access in that endpoint


### Common Endpoints

Try firing a universal POST query at the following:
- `/graphql`
- `/api`
- `/api/graphql`
- `/graphql/api`
- `/graphql/graphql`

If none, try appending `/v1`, `/v2` etc. to path. Try using different methods such as using GET instead of POST, content-type of `www-form-urlencoded` instead of `application/json`.

GraphQL responds to non-GraphQL requests with a "query not present" error.