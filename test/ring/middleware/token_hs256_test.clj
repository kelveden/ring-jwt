(ns ring.middleware.token-hs256-test
  (:require [cheshire.core :as json]
            [clojure.string :refer [split join]]
            [clojure.test :refer :all]
            [ring.middleware.encode-helper :as eh]
            [ring.middleware.token :as token])
  (:import (com.auth0.jwt.exceptions SignatureVerificationException)))

(def ^:private dummy-payload {:some "data"})
(def ^:private alg :HS256)

(deftest can-decode-validly-signed-token
  (let [payload {:field1 "whatever" :field2 "something else"}
        secret  (eh/generate-hmac-secret)
        token   (eh/encode-token payload {:alg    alg
                                          :secret secret})]
    (is (= (token/decode token {:alg    alg
                                :secret secret})
           payload))))

(deftest decoding-token-signed-with-non-matching-secret-causes-error
  (let [secret       (eh/generate-hmac-secret)
        wrong-secret (eh/generate-hmac-secret)
        token        (eh/encode-token dummy-payload {:alg    alg
                                                     :secret secret})]
    (is (thrown? SignatureVerificationException
                 (token/decode token {:alg    alg
                                      :secret wrong-secret})))))

(deftest decoding-token-with-tampered-header-causes-error
  (let [secret          (eh/generate-hmac-secret)
        token           (eh/encode-token dummy-payload {:alg    alg
                                                        :secret secret})
        [_ payload signature] (split token #"\.")
        tampered-header (eh/str->base64 (json/generate-string {:alg alg :a 1}))
        tampered-token  (join "." [tampered-header payload signature])]
    (is (thrown? SignatureVerificationException
                 (token/decode tampered-token {:alg    alg
                                               :secret secret})))))

(deftest decoding-token-with-tampered-payload-causes-error
  (let [secret           (eh/generate-hmac-secret)
        token            (eh/encode-token dummy-payload {:alg    alg
                                                         :secret secret})
        [header _ signature] (split token #"\.")
        tampered-payload (eh/str->base64 (json/generate-string {:a 1}))
        tampered-token   (join "." [header tampered-payload signature])]
    (is (thrown? SignatureVerificationException
                 (token/decode tampered-token {:alg    alg
                                               :secret secret})))))