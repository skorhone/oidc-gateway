# identity-gateway
Identity gateway for front ends with minimal OpenID Connect support.

# Architecture

## Technologies
* Spring boot
* Jetty
* Infinispan
* JWT

# TODO
1. Handle possible concurrency problems when refreshing the token (synchronize update checks and implement asynchronous handling?)
2. Improve error handling

