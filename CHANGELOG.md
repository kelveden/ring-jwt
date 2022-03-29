# 2.4.0 (2022-03-29)

> IMPORTANT: This is a major release with backward compatibility breaking changes.

## Changed
- The `reject-missing-token?` configuration flag is now `true` by default.

# 2.2.0 (2020-12-31)

## Changed
- The error messages from the bubbled Auth0 `JWTVerificationException`s are used as the response body for `401` responses
  rather than being replaced by a generic message. In doing so, this will allow easier diagnosis of authentication problems.

# 2.1.0 (2020-12-14) [195b33a](https://github.com/ovotech/ring-jwt/commit/195b33a5f7c550c68fb17e6d10b167bd4c3b1301)

## Added
- Support for new `reject-missing-token?` flag.

# 2.0.0 (2020-08-26) [f66df82](https://github.com/ovotech/ring-jwt/commit/f66df82b2d0bc6f9cfb579cc0c204725d0529963)

> IMPORTANT: This is a major release with backward compatibility breaking changes.

## Added

- Support for multiple issuers (each with their own configuration) in a single piece of middleware. The middleware will pull the issuer `iss`
from the incoming JWT and use it to lookup the appropriate algorithm from the middleware configuration to use for decoding.
(Note that the `iss` claim is not "trusted" until signature verification has succeeded.) 

## Changed
- To support multiple issuers, the format of configuration has changed so that there is a separate configuration per issuer.
See the [README](./README.md#usage) for an example.

## Removed
- `issuer` optional algorithm field has been removed. (Issuer check is now implicit based on the lookup of issuer in the
configuration.) 
 
# 1.3.0 (2020-07-14) [3bb7178](https://github.com/ovotech/ring-jwt/commit/545698b98baaba20028462d03facf72d42896e47)

## Changed

- Don't keywordize keys in the claims that are namespaced. Resolves [#11](https://github.com/ovotech/ring-jwt/issues/11).
- Bumped to latest dependencies.
- Added this CHANGELOG.md

# 1.2.5 (2020-04-08) [c3c4256](https://github.com/ovotech/ring-jwt/commit/c3c4256e3f361eca44f33ba37a13c2acf4695c27)

## Changed

- Move integrant middleware into separate library [duct.middleware.ring-jwt](https://github.com/ovotech/duct.middleware.ring-jwt) 
