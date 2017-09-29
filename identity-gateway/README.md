# identity-gateway
Application gateway with minimal OpenID Connect support.

## TODO

1. Add support for token expiration
2. Add support for token renewal (new token should be fetched before current expires)
3. Hide token contents from user by using cache and reference keys or by encrypting the token
4. Improve error handling
5. Improve performance (use asynchronous for proxying) 
