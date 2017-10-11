# oidc-gateway
This repository contains an example of using OpenID Connect based authentication in a reverse proxy for protecting web applications. 

## Authenticating Proxy vs No Proxy
Use of proxy may help implementing "single logout", if any of following statements is true:
* OP may initiate logout, but OP does not have network access to application servers
* login state is required to be shared on multiple application servers without prompts from OP

Use of proxy may help migration to OpenID Connect, if any following statements is true:
* applications are running inside Java EE container, which provides minimal or no OpenID Connect support

## Note
This code has been written to study OpenID Connect protocol. This should not be used in production

## Components
* identity-gateway - OpenID Connect relying party (RP)
* liberty-openid - Sample OpenID Connect resource server (RS) for testing purposes
* test-provider - Sample OpenID Connect provider (OP) for testing purposes
