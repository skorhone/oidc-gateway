# test-provider
Example for handling OpenID Connect based authentication and generating tokens. Test provider does not do real authentication, it merely prompts user for his credentials. These credentials are provided to client on token request

# Locations

## /auth
Authentication endpoint. Typically RP or RS redirects browser to this address in order to retrieve access code
## /token
Token endpoint. Typically RP or RS requests tokens using either access code or refresh token from this address
## /.well-known/jwks.json
JWKS endpoint. Typically RP or RS uses this endpoint to receive keys for signature verification
