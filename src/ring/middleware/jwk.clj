(ns ring.middleware.jwk
  (:import (java.net URL)
           (com.auth0.jwk GuavaCachedJwkProvider UrlJwkProvider)
           (com.auth0.jwt.interfaces RSAKeyProvider)))

(defn- new-jwk-provider
  [url headers]
  (-> (URL. url)
      (UrlJwkProvider. nil nil nil headers)
      (GuavaCachedJwkProvider.)))

(def rsa-key-provider
  (memoize
    (fn [url & [headers]]
      (let [jwk-provider (new-jwk-provider url (merge {"Accept" "application/json"}
                                                      (clojure.walk/stringify-keys headers)))]
        (reify RSAKeyProvider
          (getPublicKeyById [_ key-id]
            (-> (.get jwk-provider key-id)
                (.getPublicKey)))
          (getPrivateKey [_] nil)
          (getPrivateKeyId [_] nil))))))
