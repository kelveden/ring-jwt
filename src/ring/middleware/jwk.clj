(ns ring.middleware.jwk
  (:import (java.net URL)
           (com.auth0.jwk GuavaCachedJwkProvider UrlJwkProvider)
           (com.auth0.jwt.interfaces RSAKeyProvider)))

(defn- new-jwk-provider
  [url]
  (-> (URL. url)
      (UrlJwkProvider.)
      (GuavaCachedJwkProvider.)))

(def rsa-key-provider
  (memoize
    (fn [url]
      (let [jwk-provider (new-jwk-provider url)]
        (reify RSAKeyProvider
          (getPublicKeyById [_ key-id]
            (-> (.get jwk-provider key-id)
                (.getPublicKey)))
          (getPrivateKey [_] nil)
          (getPrivateKeyId [_] nil))))))
