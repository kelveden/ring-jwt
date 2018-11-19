(ns ring.middleware.jwt-test-utils
  "Test utility functions for use in writing tests against ring servers that have the
  ring-jwt middleware. Not designed for use in production code."
  (:require [clojure.test :refer :all]
            [cheshire.core :as json])
  (:import (com.auth0.jwt.algorithms Algorithm)
           (org.apache.commons.codec Charsets)
           (org.apache.commons.codec.binary Base64)
           (java.security KeyPairGenerator)
           (java.util UUID)))

(def ^:private algorithm->key-type
  {:RS256 "RSA"})

(defn- str->bytes
  [x]
  (.getBytes x Charsets/UTF_8))

(defn str->base64
  [x]
  (-> x
      (str->bytes)
      (Base64/encodeBase64URLSafeString)))

(defn- encode-token*
  [algorithm alg claims public-key-id]
  (let [header    (-> {:alg alg :typ "JWT" :kid public-key-id} ;; TODO check key id. should be able to get from public key?
                      (json/generate-string)
                      (str->base64))
        payload   (-> claims
                      (json/generate-string)
                      (str->base64))
        signature (->> (format "%s.%s" header payload)
                       (str->bytes)
                       (.sign algorithm)
                       (Base64/encodeBase64URLSafeString))]
    (format "%s.%s.%s" header payload signature)))

(defmulti encode-token
          "Encodes the given claims as a JWT using the given arguments as a basis."
          (fn [_ {:keys [alg]}] alg))

(defmethod encode-token :RS256
  [claims {:keys [private-key public-key-id]}]
  (-> (Algorithm/RSA256 private-key)
      (encode-token* :RS256 claims public-key-id)))

(defmethod encode-token :HS256
  [claims {:keys [secret]}]
  (-> (Algorithm/HMAC256 secret)
      (encode-token* :HS256 claims nil)))

(defn generate-key-pair
  "Generates a private/public key pair based on the specified cryptographic algorithm."
  [alg & [key-size]]
  (let [generator (doto (->> alg
                             (get algorithm->key-type)
                             (KeyPairGenerator/getInstance))
                    (.initialize (or key-size 1024)))
        key-pair  (.generateKeyPair generator)]
    {:private-key (.getPrivate key-pair)
     :public-key (.getPublic key-pair)}))

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