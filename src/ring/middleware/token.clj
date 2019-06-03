(ns ring.middleware.token
  (:require [cheshire.core :as json]
            [clojure.walk :refer [keywordize-keys]]
            [ring.middleware.jwk :as jwk]
            [clojure.spec.alpha :as s])
  (:import (com.auth0.jwt.algorithms Algorithm)
           (com.auth0.jwt JWT)
           (com.auth0.jwt.exceptions JWTDecodeException)
           (org.apache.commons.codec Charsets)
           (org.apache.commons.codec.binary Base64)
           (java.security PublicKey)))

(defn- base64->map
  [base64-str]
  (-> base64-str
      (Base64/decodeBase64)
      (String. Charsets/UTF_8)
      (json/parse-string)
      (keywordize-keys)))

(defn- decode-token*
  [algorithm token {:keys [issuer leeway-seconds]}]
  (let [add-issuer #(if issuer
                      (.withIssuer % (into-array String [issuer]))
                      %)]
    (-> algorithm
        (JWT/require)
        (.acceptLeeway (or leeway-seconds 0))
        add-issuer
        (.build)
        (.verify token)
        (.getPayload)
        (base64->map))))

(s/def ::alg #{:RS256 :HS256 :ES256})
(s/def ::issuer (s/and string? (complement clojure.string/blank?)))
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
  [token {:keys [public-key jwk-endpoint] :as opts}]
  {:pre [(s/valid? ::public-key-opts opts)]}

  (let [[public-key-type _] (s/conform ::public-key-opts opts)]
    (-> (Algorithm/ECDSA256 (case public-key-type
                              :url (jwk/jwk-provider jwk-endpoint)
                              :key public-key))
        (decode-token* token opts))))

(defmethod decode :RS256
  [token {:keys [public-key jwk-endpoint] :as opts}]
  {:pre [(s/valid? ::public-key-opts opts)]}

  (let [[public-key-type _] (s/conform ::public-key-opts opts)]
    (-> (Algorithm/RSA256 (case public-key-type
                            :url (jwk/jwk-provider jwk-endpoint)
                            :key public-key))
        (decode-token* token opts))))

(defmethod decode :HS256
  [token {:keys [secret] :as opts}]
  {:pre [(s/valid? ::secret-opts opts)]}
  (-> (Algorithm/HMAC256 secret)
      (decode-token* token opts)))
