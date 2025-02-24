(ns ring.middleware.jwt-test
  (:require [clojure.test :refer [deftest is testing]]
            [ring.middleware.jwt-test-utils :as util]
            [ring.middleware.jwt :refer [wrap-jwt]]
            [ring.middleware.test-utils :refer [build-request now-to-seconds-accuracy instant->date]]
            [clojure.string])
  (:import (clojure.lang ExceptionInfo)
           (java.util UUID)))

(def ^:private dummy-handler (constantly identity))

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

(defn- date->seconds [date]
  (/ (.getTime date) 1000))

(deftest expired-jwt-token-within-specified-leeway-is-valid
  (let [{:keys [private-key public-key]} (util/generate-key-pair :RS256)
        issuer  (str (UUID/randomUUID))
        claims  {:iss issuer
                 :exp (-> (now-to-seconds-accuracy)
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
                 :nbf (-> (now-to-seconds-accuracy)
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

(deftest issuer-is-case-sensitive
  (let [issuer  "someissuer"
        claims  {:a 1 :b 2 :iss (clojure.string/upper-case issuer)}
        handler (wrap-jwt (dummy-handler) {:issuers {issuer {:alg    :HS256
                                                             :secret "whatever"}}})
        req     (build-request claims {:alg :HS256 :secret "whatever"})
        {:keys [status body]} (handler req)]
    (is (= 401 status))
    (is (= "Unknown issuer." body))))

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

(deftest matching-audiences-are-accepted
  (let [{:keys [private-key public-key]} (util/generate-key-pair :RS256)
        issuer  (str (UUID/randomUUID))
        claims  {:a 1 :b 2 :iss issuer :aud "myaudience"}
        handler (wrap-jwt (dummy-handler) {:issuers {issuer {:alg        :RS256
                                                             :audience   "myaudience"
                                                             :public-key public-key}}})
        req     (build-request claims {:alg         :RS256
                                       :private-key private-key})
        res     (handler req)]
    (is (= claims (:claims res)))))

(deftest async-handler-arity-arguments-are-propagated-to-handler
  (let [{:keys [private-key public-key]} (util/generate-key-pair :RS256)
        issuer  (str (UUID/randomUUID))
        claims  {:a 1 :b 2 :iss issuer}
        handler (wrap-jwt (fn [_ respond raise]
                            (and (some? respond) (some? raise)))
                          {:issuers {issuer {:alg        :RS256
                                             :public-key public-key}}})
        req     (build-request claims {:alg         :RS256
                                       :private-key private-key})
        respond (fn [])
        raise   (fn [])
        res     (handler req respond raise)]
    (is (true? res))))
