(ns ring.middleware.token-rsa256-test
  (:require [cheshire.core :as json]
            [clojure.string :refer [split join]]
            [clojure.test :refer :all]
            [ring.middleware.test.encode-utils :as eu]
            [ring.middleware.token :as token])
  (:import (com.auth0.jwt.exceptions SignatureVerificationException)))

(def ^:private dummy-payload {:some "data"})
(def ^:private alg :RS256)

(deftest can-decode-validly-signed-token
  (let [payload {:field1 "whatever" :field2 "something else"}
        {:keys [private-key public-key]} (eu/generate-key-pair alg)
        token   (eu/encode-token payload {:alg         alg
                                          :private-key private-key})]
    (is (= (token/decode token {:alg        alg
                                :public-key public-key})
           payload))))

(deftest decoding-token-signed-with-non-matching-key-causes-error
  (let [{:keys [private-key]} (eu/generate-key-pair alg)
        {:keys [public-key]} (eu/generate-key-pair alg)
        token (eu/encode-token dummy-payload {:alg         alg
                                              :private-key private-key})]
    (is (thrown? SignatureVerificationException
                 (token/decode token {:alg        alg
                                      :public-key public-key})))))

(deftest decoding-token-with-tampered-header-causes-error
  (let [{:keys [private-key public-key]} (eu/generate-key-pair alg)
        token           (eu/encode-token dummy-payload {:alg         alg
                                                        :private-key private-key})
        [_ payload signature] (split token #"\.")
        tampered-header (eu/str->base64 (json/generate-string {:alg alg :a 1}))
        tampered-token  (join "." [tampered-header payload signature])]
    (is (thrown? SignatureVerificationException
                 (token/decode tampered-token {:alg        alg
                                               :public-key public-key})))))

(deftest decoding-token-with-tampered-payload-causes-error
  (let [{:keys [private-key public-key]} (eu/generate-key-pair alg)
        token            (eu/encode-token dummy-payload {:alg         alg
                                                         :private-key private-key})
        [header _ signature] (split token #"\.")
        tampered-payload (eu/str->base64 (json/generate-string {:a 1}))
        tampered-token   (join "." [header tampered-payload signature])]
    (is (thrown? SignatureVerificationException
                 (token/decode tampered-token {:alg        alg
                                               :public-key public-key})))))