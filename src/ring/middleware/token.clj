(ns ring.middleware.token
  (:require [cheshire.core :as json]
            [clojure.walk :refer [keywordize-keys]])
  (:import (com.auth0.jwt.algorithms Algorithm)
           (com.auth0.jwt JWT)
           (com.auth0.jwt.exceptions JWTDecodeException)
           (org.apache.commons.codec Charsets)
           (org.apache.commons.codec.binary Base64)))

(defn- base64->str
  [x]
  {:pre [(string? x)]}
  (-> x
      (.getBytes Charsets/UTF_8)
      (Base64/decodeBase64)
      (String. Charsets/UTF_8)))

(defn- base64->map
  [base64-str]
  (-> base64-str
      (base64->str)
      (json/parse-string)
      (keywordize-keys)))

(defn- decode-token*
  [algorithm token]
  (-> algorithm
      (JWT/require)
      (.build)
      (.verify token)
      (.getPayload)
      (base64->map)))

(defmulti decode
          "Decodes and verifies the signature of the given JWT token. The decoded claims from the token are returned."
          (fn [_ {:keys [alg]}] alg))
(defmethod decode nil
  [& _]
  (throw (JWTDecodeException. "Could not parse algorithm.")))

(defmethod decode :RS256
  [token {:keys [public-key]}]
  (-> (Algorithm/RSA256 public-key)
      (decode-token* token)))

(defmethod decode :HS256
  [token {:keys [secret]}]
  (-> (Algorithm/HMAC256 secret)
      (decode-token* token)))