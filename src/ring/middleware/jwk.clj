(ns ring.middleware.jwk
  (:import (java.net URL)
           (com.auth0.jwk GuavaCachedJwkProvider UrlJwkProvider Jwk)
           (com.auth0.jwt.interfaces RSAKeyProvider)))

(defn ^RSAKeyProvider jwk-provider
  "Creates a provider that gets the public keys for tokens"
  [url]
  (let [jwk-provider (-> (URL. url)
                         (UrlJwkProvider.)
                         (GuavaCachedJwkProvider.))]
    (reify RSAKeyProvider
      (getPublicKeyById [_, key-id]
        (-> (.get jwk-provider key-id)
            (.getPublicKey)))
      (getPrivateKey [_] nil)
      (getPrivateKeyId [_] nil))))