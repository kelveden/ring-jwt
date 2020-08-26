# 2.0.0 (2020-08-26)

> IMPORTANT: This is a major release with backward compatibility breaking changes.

## Added

- Support for multiple issuers (each with their own configuration) in a single piece of middleware. The middleware will pull the issuer `iss`
from the incoming JWT and use it to lookup the appropriate algorithm from the middleware configuration to use for decoding.
(Note that the `iss` claim is not "trusted" until signature verification has succeeded.) 

## Changed
To support multiple issuers, the format of configuration has changed so that there is a separate configuration per issuer.
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
