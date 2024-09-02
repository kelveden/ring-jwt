# ring-jwt
[![Clojars Project](https://clojars.org/net.clojars.kelveden/ring-jwt/latest-version.svg)](https://clojars.org/net.clojars.kelveden/ring-jwt)

[Ring](https://github.com/ring-clojure/ring) middleware for parsing, decoding and verifying
a [JWS](https://tools.ietf.org/html/rfc7515)-signed [JWT](https://tools.ietf.org/html/rfc7519) token from the incoming request.
(There is no explicit support for [JWE](https://tools.ietf.org/html/rfc7516) currently.)

Built on top of the excellent [auth0](https://github.com/auth0/java-jwt) JWT library.

> **Upgrading to 2.4.0 and above**: For those upgrading from versions older than `2.4.0`: This version introduced a potentially breaking
> change to the `reject-missing-token?` flag. Instead of defaulting to `false` it now defaults to `true`. So, if you are
> not already explicitly setting the field in your configuration, you will need to add an explicit `:reject-missing-token? false`.

Once wired into your ring server, the middleware will:

* Search for a JWT token on each incoming request.
  - By default, it will parse the bearer token from the `Authorization` HTTP header but this behaviour can be overridden using the `find-token-fn` setting (see usage below).
* Will add the claims it finds in the token as a clojure map against the `:claims` key on the incoming request.
* Add an empty `:claims` map to the request if no token is found.
* Respond with a `401` if the JWS signature in the token cannot be verified.
* Respond with a `401` if the option map for the matching issuer includes an `audience` setting AND there is a `aud` claim
  included on the incoming token AND those two values do not match (case-sensitively).
* Respond with a `401` if the token has expired (i.e. the [exp](https://tools.ietf.org/html/rfc7519#page-9) claim indicates a time
in the past).
  - A leeway can be specified for this check with the `leeway-seconds` setting (see usage below).
* Respond with a `401` if the token will only be active in the future (i.e. the [nbf](https://tools.ietf.org/html/rfc7519#page-10) claim indicates
a time in the future)
  - As for `exp`, the `leeway-seconds` setting can be used to introduce a leeway on this check.

## Usage
```clj
(require '[ring.middleware.jwt :as jwt])

(defn handler [request]
  (response {:foo "bar"}))

(jwt/wrap-jwt handler {:issuers {"https://some/issuer"    {:alg    :HS256
                                                           :secret "asecret"}
                                 "https://another/issuer" {:alg          :RS256
                                                           :audience     "myapi"
                                                           :jwk-endpoint "https://some/jwks/endpoint"}
                                 :no-issuer               {:alg    :HS256
                                                           :secret "anothersecret"}}})
```

Options:

* `:issuers` (mandatory): A map of issuer->cryptographic algorithm configuration. When receiving a JWT token, the middleware
will pull the issuer from the `iss` claim and use it to lookup the appropriate algorithm in the middleware configuration to verify
the JWT. (So, the `iss` claim is implicitly only "trusted" if verification succeeds.)
  - Optionally, you may include a `:no-issuer` key in the map of issuers - this value will be used if no `iss` claim is found
  in the incoming token.
* `:find-token-fn` (optional): A single-argument function that will be used to pull the (encoded) token from the request map. If unspecified
the token will be sought from the bearer token given in the `Authorization` header (i.e. an `Authorization` HTTP header of the form "Bearer TOKEN")
* `:reject-missing-token?` (optional): A flag indicating whether a request missing a JWT token will be rejected with a `401` response. Default is `true`.
If set to `false` a missing token will cause _authentication to be skipped_ - and so it is then the responsibility of your service code to determine whether incoming requests missing a token should be rejected or not.
* `:ignore-paths` (optional): set of paths for which the JWT middleware should be ignored. For requests including a `:uri` that matches one
  of the configured paths, the JWT middleware will be skipped.

### Configuring the cryptographic algorithms
Depending upon the cryptographic algorithm, a different map of options will be required. Note that, at the point your
ring middleware is wired up, ring-jwt will throw an error if it detects that the given options are invalid. 

Currently the following [JWA](https://tools.ietf.org/html/rfc7518#page-6) algorithms are
supported for the purposes of [JWS](https://tools.ietf.org/html/rfc7515):

| Algorithm                      | Options                                       |
| ------------------------------ | --------------------------------------------- |
| ECDSA using P-256 and SHA-256  | `{:alg :ES256 :public-key public-key}` <sup>[1]</sup> |
| RSASSA-PKCS-v1_5 using SHA-256 | `{:alg :RS256 :public-key public-key}` <sup>[1]</sup> |
|                                | `{:alg :RS256 :jwk-endpoint "https://your/jwk/endpoint"}` <sup>[2]</sup>| 
| HMAC using SHA-256             | `{:alg :HS256 :secret "your-secret"}`     |

* [1] `public-key` is of type `java.security.PublicKey`.
* [2] Note that the content from that JWK endpoint is cached internally for up to 10 minutes using the Auth0 [GuavaCachedJwkProvider](https://github.com/auth0/jwks-rsa-java/blob/master/src/main/java/com/auth0/jwk/GuavaCachedJwkProvider.java)
  Additional headers to be sent to the JWK endpoint in the request can be included with a `jwk-headers` map.

Additionally, the following options are supported for all issuers:

* `leeway-seconds`: The number of seconds leeway to give when verifying the expiry/active from claims
of the token (i.e. the `exp` and `nbf` claims).

## Other goodies

Keys for use with [Integrant](https://github.com/weavejester/integrant) or [Duct](https://github.com/duct-framework/duct) are available in [kelveden/duct.middleware.ring-jwt](https://github.com/kelveden/duct.middleware.ring-jwt).

## Useful links

* [JSON Web Tokens - JWT Specification](https://tools.ietf.org/html/rfc7519)
* [JSON Web Signatures - JWS Specification](https://tools.ietf.org/html/rfc7515)
* [JSON Web Algorithms - JWA Specification](https://tools.ietf.org/html/rfc7518)
* [JSON Web Keys - JWK Specification](https://tools.ietf.org/html/rfc7517)
* [jwt.io](https://jwt.io/)

## License
Distributed under the Eclipse Public License, the same as Clojure.
