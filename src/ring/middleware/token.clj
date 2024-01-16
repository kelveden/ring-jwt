(ns ring.middleware.token
  (:require [cheshire.core :as json]
            [clojure.walk :refer [postwalk]]
            [ring.middleware.jwk :as jwk]
            [clojure.spec.alpha :as s])
  (:import (com.auth0.jwt.algorithms Algorithm)
           (com.auth0.jwt JWT)
           (com.auth0.jwt.exceptions JWTDecodeException)
           (com.auth0.jwt.interfaces RSAKeyProvider)
           (java.security.interfaces ECPublicKey RSAPublicKey)
           (org.apache.commons.codec Charsets)
           (org.apache.commons.codec.binary Base64)
           (java.security PublicKey)))

(defn keywordize-non-namespaced-claims
  "Walks through the claims keywordizing them unless the key is namespaced. This is detected
  by virtue of checking for the presence of a '/' in the key name."
  [m]
  (let [namespaced? #(clojure.string/includes? % "/")
        keywordize-pair (fn [[k v]]
                          [(if (and (string? k) (not (namespaced? k)))
                             (keyword k) k)
                           v])]
    (postwalk #(cond-> % (map? %) (->> (map keywordize-pair)
                                       (into {})))
              m)))

(defn- base64->map
  [base64-str]
  (-> base64-str
      (Base64/decodeBase64)
      (String. Charsets/UTF_8)
      (json/parse-string)
      (keywordize-non-namespaced-claims)))

(defn- decode-token*
  [algorithm token {:keys [leeway-seconds]}]
  (-> algorithm
      (JWT/require)
      (.acceptLeeway (or leeway-seconds 0))
      (.build)
      (.verify ^String token)
      (.getPayload)
      (base64->map)))

(defn decode-issuer
  [token]
  (-> token JWT/decode (.getIssuer)))

(s/def ::alg #{:RS256 :HS256 :ES256})
(s/def ::issuer (s/or :string (s/and string? (complement clojure.string/blank?))
                      :keyword #{:no-issuer}))
(s/def ::leeway-seconds nat-int?)

(s/def ::secret (s/and string? (complement clojure.string/blank?)))
(s/def ::secret-opts (s/and (s/keys :req-un [::alg ::secret])
                            #(contains? #{:HS256} (:alg %))))

(s/def ::public-key #(instance? PublicKey %))
(s/def ::jwk-endpoint (s/and string? #(re-matches #"(?i)^https?://.+$" %)))
(s/def ::public-key-opts (s/and #(contains? #{:RS256 :ES256} (:alg %))
                                (s/or :key (s/keys :req-un [::alg ::public-key])
                                      :url (s/keys :req-un [::alg ::jwk-endpoint]))))

(defmulti decode
          "Decodes and verifies the signature of the given JWT token. The decoded claims from the token are returned."
          (fn [_ {:keys [alg]}] alg))
(defmethod decode nil
  [& _]
  (throw (JWTDecodeException. "Could not parse algorithm.")))

(defmethod decode :ES256
  [token {:keys [public-key] :as opts}]
  {:pre [(s/valid? ::public-key-opts opts)]}

  (let [[public-key-type _] (s/conform ::public-key-opts opts)]
    (assert (= :key public-key-type))
    (-> (Algorithm/ECDSA256 ^ECPublicKey public-key)
        (decode-token* token opts))))

(defmethod decode :RS256
  [token {:keys [public-key jwk-endpoint] :as opts}]
  {:pre [(s/valid? ::public-key-opts opts)]}

  (let [[public-key-type _] (s/conform ::public-key-opts opts)]
    (-> (case public-key-type
          :url (Algorithm/RSA256 ^RSAKeyProvider (jwk/rsa-key-provider jwk-endpoint))
          :key (Algorithm/RSA256 ^RSAPublicKey public-key))
        (decode-token* token opts))))

(defmethod decode :HS256
  [token {:keys [secret] :as opts}]
  {:pre [(s/valid? ::secret-opts opts)]}
  (-> (Algorithm/HMAC256 ^String secret)
      (decode-token* token opts)))
