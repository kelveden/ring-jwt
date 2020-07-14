# ring-jwt
[Ring](https://github.com/ring-clojure/ring) middleware for parsing, decoding and verifying
a [JWS](https://tools.ietf.org/html/rfc7515)-signed [JWT](https://tools.ietf.org/html/rfc7519) token from the incoming request.

Built on top of the excellent [auth0](https://github.com/auth0/java-jwt) JWT library.

Once wired into to your ring server, the middleware will:

* Search for a JWT token on each incoming request (see below for information on where it looks).
* Will add the claims it finds in the token as a clojure map against the `:claims` key on the incoming request.
* Add an empty `:claims` map to the request if no token is found.
* Respond with a `401` if the JWS signature in the token cannot be verified.
* Respond with a `401` if the token has expired (i.e. the [exp](https://tools.ietf.org/html/rfc7519#page-9) claim indicates a time
in the past)
* Respond with a `401` if the token will only be active in the future (i.e. the [nbf](https://tools.ietf.org/html/rfc7519#page-10) claim indicates
a time in the future)

Note that there is the option to specify a leeway for the `exp`/`nbf` checks - see usage below.

## Installation
```
[ovotech/ring-jwt "1.3.0"]
```

## Usage
```clj
(require '[ring.middleware.jwt :as jwt])

(defn handler [request]
  (response {:foo "bar"}))

(jwt/wrap-jwt handler {:alg    :HS256
                       :secret "yoursecret"})
```

Depending upon the cryptographic algorithm that is selected for the middleware, a different
map of options will be required. Note that, at the point your ring middleware is wired up, ring-jwt will
throw an error if it detects that the given options are invalid. 

Currently the following [JWA](https://tools.ietf.org/html/rfc7518#page-6) algorithms are
supported for the purposes of JWS:

| Algorithm                      | Options                                       |
| ------------------------------ | --------------------------------------------- |
| ECDSA using P-256 and SHA-256  | `{:alg :ES256 :public-key public-key}` <sup>[1]</sup> |
| RSASSA-PKCS-v1_5 using SHA-256 | `{:alg :RS256 :public-key public-key}` <sup>[1]</sup> |
|                                | `{:alg :RS256 :jwk-endpoint "https://your/jwk/endpoint"}` | 
| HMAC using SHA-256             | `{:alg :HS256 :secret "your-secret"}`     |

[1] `public-key` is of type `java.security.PublicKey`.

Additionally, the following optional options are supported:

* `leeway-seconds`: The number of seconds leeway to give when verifying the expiry/active from claims
of the token (i.e. the `exp` and `nbf` claims).
* `issuer`: The issuer of the token, if this does not match the issuer on a token a `401` will be returned.
* `find-token-fn`: The single-argument function that will be used to pull the (encoded) token from the
request map.

If a `find-token-fn` function is not specified in the options the default behaviour is to look
for the token as the bearer token given in the `Authorization` header (i.e. an `Authorization` HTTP header of the form "Bearer TOKEN")

## Other goodies

Keys for use with [Integrant](https://github.com/weavejester/integrant) or [Duct](https://github.com/duct-framework/duct) are available in [ovotech/duct.middleware.ring-jwt](https://github.com/ovotech/duct.middleware.ring-jwt).

## Useful links

* [JSON Web Tokens - JWT Specification](https://tools.ietf.org/html/rfc7519)
* [JSON Web Signatures - JWS Specification](https://tools.ietf.org/html/rfc7515)
* [JSON Web Algorithms - JWA Specification](https://tools.ietf.org/html/rfc7518)
* [JSON Web Keys - JWK Specification](https://tools.ietf.org/html/rfc7517)
* [jwt.io](https://jwt.io/)

## License
Copyright © 2018 Ovo Energy Ltd.

Distributed under the Eclipse Public License, the same as Clojure.
