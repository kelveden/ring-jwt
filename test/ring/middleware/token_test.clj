(ns ring.middleware.token-test
  (:require [cheshire.core :as json]
            [clojure.string :refer [split join]]
            [clojure.test :refer :all]
            [ring.middleware.encode-helper :as eh]
            [ring.middleware.token :as token])
  (:import (java.security KeyPairGenerator)
           (com.auth0.jwt.exceptions SignatureVerificationException JWTDecodeException)
           (org.apache.commons.codec Charsets)
           (org.apache.commons.codec.binary Base64)))

(def dummy-payload {:some "data"})
(def dummy-algorithm "RS256")

(defn str->base64
  [x]
  (-> x
      (.getBytes Charsets/UTF_8)
      (Base64/encodeBase64)
      (String. Charsets/UTF_8)))

(defn- generate-key-pair
  []
  (let [generator (doto (KeyPairGenerator/getInstance "RSA")
                    (.initialize 1024))
        key-pair (.generateKeyPair generator)]
    [(.getPrivate key-pair) (.getPublic key-pair)]))

(deftest can-decode-validly-signed-token
  (let [payload {:field1 "whatever" :field2 "something else"}
        [private-key public-key] (generate-key-pair)
        token   (eh/encode-token payload private-key dummy-algorithm)]
    (is (= (token/decode token public-key)
           payload))))

(deftest cannot-decode-signed-with-non-matching-key
  (let [[private-key] (generate-key-pair)
        [_ public-key] (generate-key-pair)
        token (eh/encode-token dummy-payload private-key dummy-algorithm)]
    (is (thrown? SignatureVerificationException
                 (token/decode token public-key)))))

(deftest cannot-decode-with-tampered-header
  (let [[private-key public-key] (generate-key-pair)
        token           (eh/encode-token dummy-payload private-key dummy-algorithm)
        [_ payload signature] (split token #"\.")
        tampered-header (str->base64 (json/generate-string {:a 1}))
        tampered-token  (join "." [tampered-header payload signature])]
    (is (thrown? JWTDecodeException
                 (token/decode tampered-token public-key)))))

(deftest cannot-decode-with-tampered-payload
  (let [[private-key public-key] (generate-key-pair)
        token            (eh/encode-token dummy-payload private-key dummy-algorithm)
        [header _ signature] (split token #"\.")
        tampered-payload (str->base64 (json/generate-string {:a 1}))
        tampered-token   (join "." [header tampered-payload signature])]
    (is (thrown? SignatureVerificationException
                 (token/decode tampered-token public-key)))))