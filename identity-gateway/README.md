# identity-gateway
Application gateway with minimal OpenID Connect support.

## TODO

1. Add support for token renewal (new token should be fetched before current expires)
2. Hide token contents from user by using cache and reference keys or by encrypting the token
3. Improve error handling
4. Improve performance (use asynchronous proxying) 
