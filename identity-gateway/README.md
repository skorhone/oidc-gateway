# identity-gateway
Application gateway with minimal OpenID Connect support.

## TODO

1. Fix state handling in gateway (add state id and sane expiration time to cookie)
2. Add support for token expiration
3. Add support for token renewal (new token should be fetched before current expires)
4. Hide token contents from user by using cache and reference keys or by encrypting the token
5. Improve error handling
6. Improve performance (use asynchronous for proxying) 
