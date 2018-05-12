(ns ring.middleware.encode-helper
  (:require [clojure.test :refer :all])
  (:import (com.auth0.jwt.algorithms Algorithm)
           (com.auth0.jwt JWT)
           (java.security KeyPairGenerator)
           (org.apache.commons.codec Charsets)
           (org.apache.commons.codec.binary Base64)
           (java.util UUID)))

(defn generate-rsa-key-pair
  []
  (let [generator (doto (KeyPairGenerator/getInstance "RSA")
                    (.initialize 1024))
        key-pair (.generateKeyPair generator)]
    [(.getPrivate key-pair) (.getPublic key-pair)]))

(defn generate-hmac-secret
  []
  (str (UUID/randomUUID)))

(defn str->base64
  [x]
  (-> x
      (.getBytes Charsets/UTF_8)
      (Base64/encodeBase64)
      (String. Charsets/UTF_8)))

(defn- encode-token*
  [algorithm claims]
  (-> (reduce (fn [acc [k v]]
                (.withClaim acc k v))
              (JWT/create)
              (clojure.walk/stringify-keys claims))
      (.sign algorithm)))

(defmulti encode-token
          "Encodes the given claims as a JWT using the given arguments as a basis."
          (fn [_ {:keys [alg]}] alg))

(defmethod encode-token :RS256
  [claims {:keys [private-key]}]
  (-> (Algorithm/RSA256 private-key)
      (encode-token* claims)))

(defmethod encode-token :HS256
  [claims {:keys [secret]}]
  (-> (Algorithm/HMAC256 secret)
      (encode-token* claims)))