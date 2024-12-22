(ns ring.middleware.jwt-test-utils
  "Test utility functions for use in writing tests against ring servers that have the
  ring-jwt middleware. Not designed for use in production code."
  (:require [clojure.walk :refer [stringify-keys walk]]
            [cheshire.core :as json])
  (:import (com.auth0.jwt.algorithms Algorithm)
           (org.apache.commons.codec Charsets)
           (org.apache.commons.codec.binary Base64)
           (java.security KeyPairGenerator)
           (java.util UUID HashMap)
           (com.auth0.jwt.interfaces RSAKeyProvider ECDSAKeyProvider)
           (com.auth0.jwt JWT JWTCreator$Builder)
           (java.nio.charset StandardCharsets)))

(def ^:private algorithm->key-type
  {:RS256 "RSA"
   :ES256 "EC"})

(def ^:private algorithm->key-size
  {:RS256 512
   :ES256 256})

(defn- str->bytes
  [x]
  (.getBytes x Charsets/UTF_8))

(defn str->base64
  [x]
  (-> x
      (str->bytes)
      (Base64/encodeBase64URLSafeString)))

(defn- walk-map [map f]
  (walk f identity map))

(defn- recurse-hash-map [map]
  (let [updated     (walk-map map (fn [[k v]] (if (map? v) [k (recurse-hash-map v)] [k v])))
        stringified (stringify-keys updated)]
    (HashMap. stringified)))

;; The java library refuses to accept maps as claims so we are using reflection here to force maps into the claims
(def ^:private payload-claims
  (.getDeclaredField JWTCreator$Builder "payloadClaims"))

(defn- force-add-claim [token key value]
  (.setAccessible payload-claims true)
  (let [claims (.get payload-claims token)]
    (.put claims key value))
  token)

(defn add-claim [token [k v]]
  (let [key (name k)]
    (cond
      (map? v) (force-add-claim token key (recurse-hash-map v))
      (vector? v) (force-add-claim token key v)
      :else (.withClaim token key v))))

(defn- encode-token*
  [algorithm claims]
  (let [jwt     (JWT/create)
        payload (->> claims
                     (reduce add-claim jwt))]
    (.sign payload algorithm)))

(defmulti encode-token
          "Encodes the given claims as a JWT using the given arguments as a basis."
          (fn [_ {:keys [alg]}] alg))

(defmethod encode-token :RS256
  [claims {:keys [private-key key-id public-key]}]
  (let [algorithm (Algorithm/RSA256
                    (reify RSAKeyProvider
                      (getPublicKeyById [_, _] public-key)
                      (getPrivateKey [_] private-key)
                      (getPrivateKeyId [_] key-id)))]
    (encode-token* algorithm claims)))

(defmethod encode-token :ES256
  [claims {:keys [private-key key-id public-key]}]
  (let [algorithm (Algorithm/ECDSA256
                    (reify ECDSAKeyProvider
                      (getPublicKeyById [_, _] public-key)
                      (getPrivateKey [_] private-key)
                      (getPrivateKeyId [_] key-id)))]
    (encode-token* algorithm claims)))

(defmethod encode-token :HS256
  [claims {:keys [secret]}]
  (-> (Algorithm/HMAC256 secret)
      (encode-token* claims)))

(defn generate-key-pair
  "Generates a private/public key pair based on the specified cryptographic algorithm."
  [alg & {:keys [key-size]}]
  (let [key-size-final (or key-size
                           (algorithm->key-size alg))
        generator      (doto (->> alg
                                  (get algorithm->key-type)
                                  (KeyPairGenerator/getInstance))
                         (.initialize key-size-final))
        key-pair       (.generateKeyPair generator)]
    {:private-key (.getPrivate key-pair)
     :public-key  (.getPublic key-pair)}))

(defn generate-hmac-secret
  "Generates a random string to use as a HMAC secret."
  []
  (str (UUID/randomUUID)))

(defn add-jwt-token
  "Sets the Authorization header on the specified request as a JWT-encoded token based
  on the given claims and algorithm."
  [req claims alg-opts]
  (assoc-in req [:headers "Authorization"]
            (str "Bearer " (encode-token claims alg-opts))))

(defn generate-jwk-response
  "Creates the JWK response for an RS256 public key with the key id.
  This should be returned by your JWK endpoint in tests"
  [key-id public-key]
  (let [base64-encode-big-endian #(-> (.toByteArray %)
                                      (Base64/encodeBase64URLSafe)
                                      (String. StandardCharsets/UTF_8))]
    (json/generate-string
      {:keys [{:kid key-id
               :kty (.getAlgorithm public-key)
               :alg "RS256"
               :use "sig"
               :e   (base64-encode-big-endian (.getPublicExponent public-key))
               :n   (base64-encode-big-endian (.getModulus public-key))}]})))
