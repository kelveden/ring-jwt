# ring-jwt
[Ring](https://github.com/ring-clojure/ring) middleware for parsing, decoding and verifying
a [JWS](https://tools.ietf.org/html/rfc7515)-signed [JWT](https://tools.ietf.org/html/rfc7519) token from the incoming request.

Built on top of the excellent [auth0](https://github.com/auth0/java-jwt) JWT library.

## Installation
```
[ovotech/ring-jwt "0.1.0"]
```

## Usage
```clj
(require '[ring.middleware.jwt :refer [wrap-jwt]])

(defn handler [request]
  (response {:foo "bar"}))

(jwt/wrap-jwt handler {:alg        :RS256
                       :public-key "yourpublickey"})
```

Depending upon the cryptographic algorithm that is selected for the middleware, a different
map of options will be required.

Currently the following [JWA](https://tools.ietf.org/html/rfc7518#page-6) algorithms are
supported for the purposes of JWS:

| Algorithm                      | Options                          |                   |
| ------------------------------ | -------------------------------- | ----------------- |
| RSASSA-PKCS-v1_5 using SHA-256 | `:alg`                           | `:RS256`          |
|                                | `:public-key`                    | `your-public-key` |
| HMAC using SHA-256             | `:alg`                           | `:HS256`          |
|                                | `:secret`                        | `your-secret`     |

### Finding the token on the request
Currently the library looks in order from the following locations:

1. `Authorization` header bearer token (i.e. an `Authorization` HTTP header of the form "Bearer TOKEN")

## Useful links:

* [JWT Specification](https://tools.ietf.org/html/rfc7519)
* [JWS Specification](https://tools.ietf.org/html/rfc7515)
* [JWA Specification](https://tools.ietf.org/html/rfc7518)
* [jwt.io](https://jwt.io/)

## License
Copyright © 2018 Ovo Energy Ltd.

Distributed under the Eclipse Public License, the same as Clojure.
