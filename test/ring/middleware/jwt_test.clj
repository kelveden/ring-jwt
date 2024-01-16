(ns ring.middleware.jwt-test
  (:require [cheshire.core :as json]
            [clojure.string :refer [split join]]
            [clojure.test :refer :all]
            [ring.middleware.jwt-test-utils :as util]
            [ring.middleware.jwt :refer [wrap-jwt]])
  (:import (clojure.lang ExceptionInfo)
           (java.time Instant)
           (java.util Date UUID)
           (com.auth0.jwt.exceptions AlgorithmMismatchException)))

(def ^:private dummy-handler (constantly identity))

(defn- build-request
  [claims alg-opts]
  (util/add-jwt-token {} claims alg-opts))

(defn- epoch-seconds-instant []
  (-> (Instant/now)
      (.getEpochSecond)
      (Instant/ofEpochSecond)))

(defn- instant->date [instant]
  (Date/from instant))

(deftest claims-from-valid-jwt-token-in-authorization-header-are-added-to-request
  (let [{:keys [private-key public-key]} (util/generate-key-pair :RS256)
        issuer  (str (UUID/randomUUID))
        claims  {:a 1 :b 2 :iss issuer}
        handler (wrap-jwt (dummy-handler) {:issuers {issuer {:alg        :RS256
                                                             :public-key public-key}}})
        req     (build-request claims {:alg         :RS256
                                       :private-key private-key})
        res     (handler req)]
    (is (= claims (:claims res)))))

(deftest can-use-finder-function-to-locate-token
  (let [{:keys [private-key public-key]} (util/generate-key-pair :RS256)
        issuer  (str (UUID/randomUUID))
        claims  {:a 1 :b 2 :iss issuer}
        handler (wrap-jwt (dummy-handler) {:issuers       {issuer {:alg        :RS256
                                                                   :public-key public-key}}
                                           :find-token-fn (fn [{:keys [headers]}] (get headers "X-Whatever"))})
        token   (util/encode-token claims {:alg         :RS256
                                           :private-key private-key})
        req     {:headers {"X-Whatever" token}}
        res     (handler req)]
    (is (= claims (:claims res)))))

(deftest jwt-token-signed-with-wrong-algorithm-causes-401
  (let [{:keys [private-key]} (util/generate-key-pair :RS256)
        issuer  (str (UUID/randomUUID))
        claims  {:a 1 :b 2 :iss issuer}
        handler (wrap-jwt (dummy-handler) {:issuers {issuer {:alg    :HS256
                                                             :secret (util/generate-hmac-secret)}}})
        req     (build-request claims {:alg         :RS256
                                       :private-key private-key})
        {:keys [body status]} (handler req)]
    (is (= 401 status))
    (is (= "The provided Algorithm doesn't match the one defined in the JWT's Header." body))))

(deftest jwt-token-signed-with-wrong-issuer-causes-401
  (let [{:keys [private-key]} (util/generate-key-pair :RS256)
        issuer  (str (UUID/randomUUID))
        claims  {:a 1 :b 2 :iss (str (UUID/randomUUID))}
        handler (wrap-jwt (dummy-handler) {:issuers {issuer {:alg    :HS256
                                                             :secret (util/generate-hmac-secret)}}})
        req     (build-request claims {:alg         :RS256
                                       :private-key private-key})
        {:keys [body status]} (handler req)]
    (is (= 401 status))
    (is (= "Unknown issuer." body))))

(deftest jwt-token-with-tampered-header-causes-401
  (let [{:keys [private-key public-key]} (util/generate-key-pair :RS256)
        issuer          (str (UUID/randomUUID))
        claims          {:a 1 :b 2 :iss issuer}
        token           (util/encode-token claims {:alg         :RS256
                                                   :private-key private-key})
        [_ payload signature] (split token #"\.")
        tampered-header (util/str->base64 (json/generate-string {:alg :RS256 :a 1}))
        tampered-token  (join "." [tampered-header payload signature])

        handler         (wrap-jwt (dummy-handler) {:issuers {issuer {:alg        :RS256
                                                                     :public-key public-key}}})
        req             {:headers {"Authorization" (str "Bearer " tampered-token)}}
        {:keys [body status]} (handler req)]
    (is (= 401 status))
    (is (= "The Token's Signature resulted invalid when verified using the Algorithm: SHA256withRSA" body))))

(deftest jwt-token-with-tampered-payload-causes-401
  (let [{:keys [private-key public-key]} (util/generate-key-pair :RS256)
        issuer           (str (UUID/randomUUID))
        claims           {:a 1 :b 2 :iss issuer}
        token            (util/encode-token claims {:alg         :RS256
                                                    :private-key private-key})

        [header _ signature] (split token #"\.")
        tampered-payload (util/str->base64 (json/generate-string {:a 1 :iss issuer}))
        tampered-token   (join "." [header tampered-payload signature])

        handler          (wrap-jwt (dummy-handler) {:issuers {issuer {:alg        :RS256
                                                                      :public-key public-key}}})
        req              {:headers {"Authorization" (str "Bearer " tampered-token)}}
        {:keys [body status]} (handler req)]
    (is (= 401 status))
    (is (= "The Token's Signature resulted invalid when verified using the Algorithm: SHA256withRSA" body))))

(deftest expired-jwt-token-causes-401
  (let [{:keys [private-key public-key]} (util/generate-key-pair :RS256)
        issuer  (str (UUID/randomUUID))
        claims  {:iss issuer
                 :exp (-> (epoch-seconds-instant)
                          (.minusSeconds 1)
                          (instant->date))}
        handler (wrap-jwt (dummy-handler) {:issuers {issuer {:alg        :RS256
                                                             :public-key public-key}}})
        req     (build-request claims {:alg         :RS256
                                       :private-key private-key})
        {:keys [body status]} (handler req)]
    (is (= 401 status))
    (is (clojure.string/starts-with? body "The Token has expired on"))))

(deftest future-active-jwt-token-causes-401
  (let [{:keys [private-key public-key]} (util/generate-key-pair :RS256)
        issuer  (str (UUID/randomUUID))
        claims  {:iss issuer
                 :nbf (-> (epoch-seconds-instant)
                          (.plusSeconds 1)
                          (instant->date))}
        handler (wrap-jwt (dummy-handler) {:issuers {issuer {:alg        :RS256
                                                             :public-key public-key}}})
        req     (build-request claims {:alg         :RS256
                                       :private-key private-key})
        {:keys [body status]} (handler req)]
    (is (= 401 status))
    (is (clojure.string/starts-with? body "The Token can't be used before"))))

(defn- date->seconds [date]
  (/ (.getTime date) 1000))

(deftest expired-jwt-token-within-specified-leeway-is-valid
  (let [{:keys [private-key public-key]} (util/generate-key-pair :RS256)
        issuer  (str (UUID/randomUUID))
        claims  {:iss issuer
                 :exp (-> (epoch-seconds-instant)
                          (.minusSeconds 100)
                          (instant->date))}
        handler (wrap-jwt (dummy-handler) {:issuers {issuer {:alg            :RS256
                                                             :public-key     public-key
                                                             :leeway-seconds 1000}}})
        req     (build-request claims {:alg         :RS256
                                       :private-key private-key})
        res     (handler req)]
    (is (= (update claims :exp date->seconds) (:claims res)))))

(deftest future-jwt-token-within-specified-leeway-is-valid
  (let [{:keys [private-key public-key]} (util/generate-key-pair :RS256)
        issuer  (str (UUID/randomUUID))
        claims  {:iss issuer
                 :nbf (-> (epoch-seconds-instant)
                          (.plusSeconds 100)
                          (instant->date))}
        handler (wrap-jwt (dummy-handler) {:issuers {issuer {:alg            :RS256
                                                             :public-key     public-key
                                                             :leeway-seconds 1000}}})
        req     (build-request claims {:alg         :RS256
                                       :private-key private-key})
        res     (handler req)]
    (is (= (update claims :nbf date->seconds) (:claims res)))))

(deftest test-object-and-vector-claims-can-be-added
  (let [{:keys [private-key public-key]} (util/generate-key-pair :RS256)
        issuer  (str (UUID/randomUUID))
        claims  {:foo {:a 1 :b 2
                       :c {:d 3}
                       :e [4 5 6]}
                 :bar [1 2 3]
                 :iss issuer}
        handler (wrap-jwt (dummy-handler) {:issuers {issuer {:alg        :RS256
                                                             :public-key public-key}}})
        req     (build-request claims {:alg         :RS256
                                       :private-key private-key})
        res     (handler req)]
    (is (= claims (:claims res)))))

(deftest allow-http-for-jwk
  (let [issuer (str (UUID/randomUUID))]
    (wrap-jwt (dummy-handler) {:issuers {issuer {:alg          :RS256
                                                 :jwk-endpoint "http://my/jwk"
                                                 :key-id       (str (str (UUID/randomUUID)))}}})))

(testing "invalid options"
  (deftest missing-option-causes-error
    (let [issuer (str (UUID/randomUUID))]
      (is (thrown-with-msg? ExceptionInfo #"Invalid options."
                            (wrap-jwt (dummy-handler) {:issuers {issuer {:alg    :HS256
                                                                         :bollox "whatever"}}})))))

  (deftest incorrect-option-type-causes-error
    (let [issuer (str (UUID/randomUUID))]
      (is (thrown-with-msg? ExceptionInfo #"Invalid options."
                            (wrap-jwt (dummy-handler) {:issuers {issuer {:alg    :HS256
                                                                         :secret 1}}})))))

  (deftest option-from-wrong-algorithm-causes-error
    (let [issuer (str (UUID/randomUUID))]
      (is (thrown-with-msg? ExceptionInfo #"Invalid options."
                            (wrap-jwt (dummy-handler) {:issuers {issuer {:alg    :RS256
                                                                         :secret "whatever"}}})))))

  (deftest extra-unsupported-option-does-not-cause-error
    (let [issuer (str (UUID/randomUUID))]
      (wrap-jwt (dummy-handler) {:issuers {issuer {:alg    :HS256
                                                   :secret "somesecret"
                                                   :bollox "whatever"}}}))))

(deftest namespaced-claims-are-not-keywordized
  (let [{:keys [private-key public-key]} (util/generate-key-pair :RS256)
        issuer  (str (UUID/randomUUID))
        claims  {"http://some/private/claim" 1
                 "another/namespaced-claim"  2
                 "iss"                       issuer}
        handler (wrap-jwt (dummy-handler) {:issuers {issuer {:alg        :RS256
                                                             :public-key public-key}}})
        req     (build-request claims {:alg         :RS256
                                       :private-key private-key})
        res     (handler req)]
    (is (= (-> claims
               (assoc :iss issuer)
               (dissoc "iss"))
           (:claims res)))))

(deftest decoding-algorithm-is-selected-by-issuer
  (let [{private-key1 :private-key public-key1 :public-key} (util/generate-key-pair :RS256)
        {private-key2 :private-key public-key2 :public-key} (util/generate-key-pair :RS256)
        issuer1 (str (UUID/randomUUID))
        issuer2 (str (UUID/randomUUID))
        claims1 {:a 1 :b 2 :iss issuer1}
        claims2 {:a 1 :b 2 :iss issuer2}
        handler (wrap-jwt (dummy-handler) {:issuers {issuer1 {:alg        :RS256
                                                              :public-key public-key1}
                                                     issuer2 {:alg        :RS256
                                                              :public-key public-key2}}})]
    (is (= claims1 (->> {:alg         :RS256
                         :private-key private-key1}
                        (build-request claims1)
                        (handler)
                        :claims)))
    (is (= claims2 (->> {:alg         :RS256
                         :private-key private-key2}
                        (build-request claims2)
                        (handler)
                        :claims)))))

(deftest unknown-issuer-causes-401
  (let [issuer  (str (UUID/randomUUID))
        claims  {:a 1 :b 2 :iss "anotherissuer"}
        handler (wrap-jwt (dummy-handler) {:issuers {issuer {:alg    :HS256
                                                             :secret "whatever"}}})
        req     (build-request claims {:alg :HS256 :secret "whatever"})
        {:keys [status body]} (handler req)]
    (is (= 401 status))
    (is (= "Unknown issuer." body))))

(deftest issuer-is-case-sensitive
  (let [issuer  "someissuer"
        claims  {:a 1 :b 2 :iss (clojure.string/upper-case issuer)}
        handler (wrap-jwt (dummy-handler) {:issuers {issuer {:alg    :HS256
                                                             :secret "whatever"}}})
        req     (build-request claims {:alg :HS256 :secret "whatever"})
        {:keys [status body]} (handler req)]
    (is (= 401 status))
    (is (= "Unknown issuer." body))))

(deftest missing-token-causes-401-by-default
  (let [{:keys [public-key]} (util/generate-key-pair :RS256)
        issuer  (str (UUID/randomUUID))
        handler (wrap-jwt (fn [_] {:status 200})
                          {:issuers {issuer {:alg        :RS256
                                             :public-key public-key}}})
        req     {}
        {:keys [status]} (handler req)]
    (is (= 401 status))))

(deftest missing-token-is-ignored-when-configured-not-to-reject-missing-tokens
  (let [{:keys [public-key]} (util/generate-key-pair :RS256)
        issuer  (str (UUID/randomUUID))
        handler (wrap-jwt (fn [_] {:status 200})
                          {:issuers               {issuer {:alg        :RS256
                                                           :public-key public-key}}
                           :reject-missing-token? false})
        req     {}
        {:keys [status]} (handler req)]
    (is (= 200 status))))

(deftest missing-token-causes-401-if-configured-to-reject-missing-tokens
  (let [{:keys [public-key]} (util/generate-key-pair :RS256)
        issuer  (str (UUID/randomUUID))
        handler (wrap-jwt (fn [_] {:status 200})
                          {:issuers               {issuer {:alg        :RS256
                                                           :public-key public-key}}
                           :reject-missing-token? true})
        req     {}
        {:keys [status]} (handler req)]
    (is (= 401 status))))

(deftest jwt-token-signed-with-no-iss-is-ok-when-fallback-registered
  (let [{:keys [private-key public-key]} (util/generate-key-pair :RS256)
        claims  {:a 1 :b 2}
        handler (wrap-jwt (fn [_] {:status 200})
                          {:issuers {:no-issuer {:alg        :RS256
                                                 :public-key public-key}}})
        req     (build-request claims {:alg         :RS256
                                       :private-key private-key})
        {:keys [status]} (handler req)]
    (is (= 200 status))))

(deftest jwt-token-signed-with-no-iss-causes-failure-when-no-fallback-registered
  (let [{:keys [private-key]} (util/generate-key-pair :RS256)
        claims  {:a 1 :b 2}
        handler (wrap-jwt (fn [_] {:status 200})
                          {:issuers {}})
        req     (build-request claims {:alg         :RS256
                                       :private-key private-key})
        {:keys [status body]} (handler req)]
    (is (= 401 status))
    (is (= "Unknown issuer." body))))

(deftest jwt-token-signed-by-unknown-issuer-is-not-ok-even-when-fallback-registered
  (let [{:keys [private-key public-key]} (util/generate-key-pair :RS256)
        claims  {:a 1 :b 2 :iss (str (UUID/randomUUID))}
        handler (wrap-jwt (fn [_] {:status 200})
                          {:issuers {:no-issuer {:alg        :RS256
                                                 :public-key public-key}}})
        req     (build-request claims {:alg         :RS256
                                       :private-key private-key})
        {:keys [status body]} (handler req)]
    (is (= 401 status))
    (is (= "Unknown issuer." body))))

(deftest request-with-no-token-is-processed-when-ignore-paths-configured
  (let [{:keys [public-key]} (util/generate-key-pair :RS256)
        issuer  (str (UUID/randomUUID))
        handler (wrap-jwt (fn [_] {:status 200})
                          {:issuers               {issuer {:alg        :RS256
                                                           :public-key public-key}}
                           :reject-missing-token? false
                           :ignore-paths          #{"/ping"}})
        req     {:uri "/ping"}
        {:keys [status]} (handler req)]
    (is (= 200 status))))