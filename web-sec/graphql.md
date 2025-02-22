# GraphQL

## Syntax Cheatsheet

Query language for REST APIs: https://devhints.io/graphql


## Enumerating Endpoints

### Universal Queries

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