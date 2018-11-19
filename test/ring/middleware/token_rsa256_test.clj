(ns ring.middleware.token-rsa256-test
  (:require [cheshire.core :as json]
            [clojure.string :refer [split join]]
            [clojure.test :refer :all]
            [ring.middleware.jwt-test-utils :as util]
            [ring.middleware.token :as token]
            [ring.middleware.jwk :as jwk])
  (:import (com.auth0.jwt.exceptions SignatureVerificationException)
           (java.util UUID)
           (com.auth0.jwt.interfaces RSAKeyProvider)))

(def ^:private dummy-payload {:some "data"})
(def ^:private alg :RS256)
(def ^:private issuer "me")

(deftest can-decode-validly-signed-token
  (let [payload {:field1 "whatever" :field2 "something else"}
        {:keys [private-key public-key]} (util/generate-key-pair alg)
        token   (util/encode-token payload {:alg         alg
                                            :issuer      issuer
                                            :private-key private-key})]
    (is (= (token/decode token {:alg        alg
                                :issuer     issuer
                                :public-key public-key})
           (merge payload {:iss issuer})))))

(deftest can-decode-token-based-on-jwk-provider-url
  (let [payload      {:field1 "whatever" :field2 "something else"}
        {:keys [private-key public-key]} (util/generate-key-pair alg)
        key-id       (str (UUID/randomUUID))
        token        (util/encode-token payload {:alg           alg
                                                 :issuer        issuer
                                                 :public-key-id key-id
                                                 :private-key   private-key})
        jwk-endpoint "https://my/jwk"]

    (with-redefs [jwk/jwk-provider (fn [u]
                                     (reify RSAKeyProvider
                                       (getPublicKeyById [_, k]
                                         (when (and (= u jwk-endpoint) (= k key-id))
                                           public-key))
                                       (getPrivateKey [_] nil)
                                       (getPrivateKeyId [_] nil)))]
      (is (= (token/decode token {:alg          alg
                                  :issuer       issuer
                                  :jwk-endpoint jwk-endpoint})
             (merge payload {:iss issuer}))))))

(deftest decoding-token-signed-with-non-matching-key-causes-error
  (let [{:keys [private-key]} (util/generate-key-pair alg)
        {:keys [public-key]} (util/generate-key-pair alg)
        token (util/encode-token dummy-payload {:alg         alg
                                                :issuer      issuer
                                                :private-key private-key})]
    (is (thrown? SignatureVerificationException
                 (token/decode token {:alg        alg
                                      :issuer issuer
                                      :public-key public-key})))))

(deftest decoding-token-with-tampered-header-causes-error
  (let [{:keys [private-key public-key]} (util/generate-key-pair alg)
        token           (util/encode-token dummy-payload {:alg         alg
                                                          :issuer      issuer
                                                          :private-key private-key})
        [_ payload signature] (split token #"\.")
        tampered-header (util/str->base64 (json/generate-string {:alg alg :a 1}))
        tampered-token  (join "." [tampered-header payload signature])]
    (is (thrown? SignatureVerificationException
                 (token/decode tampered-token {:alg        alg
                                               :issuer     issuer
                                               :public-key public-key})))))

(deftest decoding-token-with-tampered-payload-causes-error
  (let [{:keys [private-key public-key]} (util/generate-key-pair alg)
        token            (util/encode-token dummy-payload {:alg         alg
                                                           :issuer      issuer
                                                           :private-key private-key})
        [header _ signature] (split token #"\.")
        tampered-payload (util/str->base64 (json/generate-string {:a 1}))
        tampered-token   (join "." [header tampered-payload signature])]
    (is (thrown? SignatureVerificationException
                 (token/decode tampered-token {:alg        alg
                                               :issuer     issuer
                                               :public-key public-key})))))