(ns ring.middleware.token-hs256-test
  (:require [cheshire.core :as json]
            [clojure.string :refer [split join]]
            [clojure.test :refer [deftest is]]
            [ring.middleware.jwt-test-utils :as util]
            [ring.middleware.token :as token])
  (:import (com.auth0.jwt.exceptions SignatureVerificationException)))

(def ^:private dummy-payload {:some "data"})
(def ^:private alg :HS256)

(deftest can-decode-validly-signed-token
  (let [payload {:field1 "whatever" :field2 "something else"}
        secret  (util/generate-hmac-secret)
        token   (util/encode-token payload {:alg    alg
                                            :secret secret})]
    (is (= (token/decode token {:alg    alg
                                :secret secret})
           payload))))

(deftest can-decode-validly-signed-token-with-issuer
  (let [issuer  "me"
        payload {:field1 "whatever" :field2 "something else" :iss issuer}
        secret  (util/generate-hmac-secret)
        token   (util/encode-token payload {:alg    alg
                                            :secret secret})]
    (is (= (token/decode token {:alg    alg
                                :issuer issuer
                                :secret secret})
           payload))))

(deftest decoding-token-signed-with-non-matching-secret-causes-error
  (let [secret       (util/generate-hmac-secret)
        wrong-secret (util/generate-hmac-secret)
        token        (util/encode-token dummy-payload {:alg    alg
                                                       :secret secret})]
    (is (thrown? SignatureVerificationException
                 (token/decode token {:alg    alg
                                      :secret wrong-secret})))))

(deftest decoding-token-with-tampered-header-causes-error
  (let [secret          (util/generate-hmac-secret)
        token           (util/encode-token dummy-payload {:alg    alg
                                                          :secret secret})
        [_ payload signature] (split token #"\.")
        tampered-header (util/str->base64 (json/generate-string {:alg alg :a 1}))
        tampered-token  (join "." [tampered-header payload signature])]
    (is (thrown? SignatureVerificationException
                 (token/decode tampered-token {:alg    alg
                                               :secret secret})))))

(deftest decoding-token-with-tampered-payload-causes-error
  (let [secret           (util/generate-hmac-secret)
        token            (util/encode-token dummy-payload {:alg    alg
                                                           :secret secret})
        [header _ signature] (split token #"\.")
        tampered-payload (util/str->base64 (json/generate-string {:a 1}))
        tampered-token   (join "." [header tampered-payload signature])]
    (is (thrown? SignatureVerificationException
                 (token/decode tampered-token {:alg    alg
                                               :secret secret})))))