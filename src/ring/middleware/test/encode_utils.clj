(ns ring.middleware.test.encode-utils
  (:require [clojure.test :refer :all]
            [cheshire.core :as json])
  (:import (com.auth0.jwt.algorithms Algorithm)
           (org.apache.commons.codec Charsets)
           (org.apache.commons.codec.binary Base64)
           (java.security KeyPairGenerator)
           (java.util UUID)))

(def ^:private algorithm->key-type
  {:RS256 "RSA"})

(defn generate-key-pair
  [alg & [key-size]]
  (let [generator (doto (->> alg
                             (get algorithm->key-type)
                             (KeyPairGenerator/getInstance))
                    (.initialize (or key-size 1024)))
        key-pair  (.generateKeyPair generator)]
    {:private-key (.getPrivate key-pair)
     :public-key (.getPublic key-pair)}))

(defn generate-hmac-secret
  []
  (str (UUID/randomUUID)))

(defn str->bytes
  [x]
  (.getBytes x Charsets/UTF_8))

(defn str->base64
  [x]
  (-> x
      (str->bytes)
      (Base64/encodeBase64URLSafeString)))

(defn- encode-token*
  [algorithm alg claims]
  (let [header    (-> {:alg alg :typ "JWT"}
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
  [claims {:keys [private-key]}]
  (-> (Algorithm/RSA256 private-key)
      (encode-token* :RS256 claims)))

(defmethod encode-token :HS256
  [claims {:keys [secret]}]
  (-> (Algorithm/HMAC256 secret)
      (encode-token* :HS256 claims)))
