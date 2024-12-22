(ns ring.middleware.jwt-authz-error-test
  (:require [cheshire.core :as json]
            [clojure.string :refer [split join]]
            [clojure.test :refer [deftest is]]
            [ring.middleware.jwt-test-utils :as util]
            [ring.middleware.jwt :refer [wrap-jwt]]
            [ring.middleware.test-utils :refer [build-request now-to-seconds-accuracy instant->date]])
  (:import (java.util UUID)))

(def ^:private dummy-handler (constantly identity))

(deftest jwt-token-signed-with-wrong-algorithm-causes-401
  (let [{:keys [private-key]} (util/generate-key-pair :RS256)
        issuer (str (UUID/randomUUID))
        claims {:a 1 :b 2 :iss issuer}
        req    (build-request claims {:alg         :RS256
                                      :private-key private-key})
        config {:issuers {issuer {:alg    :HS256
                                  :secret (util/generate-hmac-secret)}}}]
    (let [handler (wrap-jwt (dummy-handler) config)
          {:keys [body status headers]} (handler req)]
      (is (= 401 status))
      (is (= "The provided Algorithm doesn't match the one defined in the JWT's Header." body))
      (is (nil? headers))

      (let [respond #(assoc %1 :responded? true)
            {:keys [responded? status]} (handler req respond)]
        (is (= 401 status))
        (is (true? responded?))))

    (let [handler (wrap-jwt (dummy-handler)
                            (assoc config :oauth-error-support {:enabled? true}))
          {:keys [status headers]} (handler req)]
      (is (= 401 status))
      (is (= "Bearer error=\"invalid_token\"" (:WWW-Authenticate headers))))))

(deftest jwt-token-signed-with-wrong-issuer-causes-401
  (let [{:keys [private-key]} (util/generate-key-pair :RS256)
        issuer (str (UUID/randomUUID))
        claims {:a 1 :b 2 :iss (str (UUID/randomUUID))}
        config {:issuers {issuer {:alg    :HS256
                                  :secret (util/generate-hmac-secret)}}}
        req    (build-request claims {:alg         :RS256
                                      :private-key private-key})]
    (let [handler (wrap-jwt (dummy-handler) config)
          {:keys [body status headers]} (handler req)]
      (is (= 401 status))
      (is (= "Unknown issuer." body))
      (is (nil? headers))

      (let [respond #(assoc %1 :responded? true)
            {:keys [responded? status]} (handler req respond)]
        (is (= 401 status))
        (is (true? responded?))))

    (let [handler (wrap-jwt (dummy-handler)
                            (assoc config :oauth-error-support {:enabled? true}))
          {:keys [status headers]} (handler req)]
      (is (= 401 status))
      (is (= "Bearer error=\"invalid_token\"" (:WWW-Authenticate headers))))))

(deftest jwt-token-with-tampered-header-causes-401
  (let [{:keys [private-key public-key]} (util/generate-key-pair :RS256)
        issuer          (str (UUID/randomUUID))
        claims          {:a 1 :b 2 :iss issuer}
        token           (util/encode-token claims {:alg         :RS256
                                                   :private-key private-key})
        [_ payload signature] (split token #"\.")
        tampered-header (util/str->base64 (json/generate-string {:alg :RS256 :a 1}))
        tampered-token  (join "." [tampered-header payload signature])

        config          {:issuers {issuer {:alg        :RS256
                                           :public-key public-key}}}
        req             {:headers {"Authorization" (str "Bearer " tampered-token)}}]
    (let [handler (wrap-jwt (dummy-handler) config)
          {:keys [body status headers]} (handler req)]
      (is (= 401 status))
      (is (= "The Token's Signature resulted invalid when verified using the Algorithm: SHA256withRSA" body))
      (is (nil? headers))

      (let [respond #(assoc %1 :responded? true)
            {:keys [responded? status]} (handler req respond)]
        (is (= 401 status))
        (is (true? responded?))))

    (let [handler (wrap-jwt (dummy-handler)
                            (assoc config :oauth-error-support {:enabled? true}))
          {:keys [status headers]} (handler req)]
      (is (= 401 status))
      (is (= "Bearer error=\"invalid_token\"" (:WWW-Authenticate headers))))))

(deftest jwt-token-with-tampered-payload-causes-401
  (let [{:keys [private-key public-key]} (util/generate-key-pair :RS256)
        issuer           (str (UUID/randomUUID))
        claims           {:a 1 :b 2 :iss issuer}
        token            (util/encode-token claims {:alg         :RS256
                                                    :private-key private-key})

        [header _ signature] (split token #"\.")
        tampered-payload (util/str->base64 (json/generate-string {:a 1 :iss issuer}))
        tampered-token   (join "." [header tampered-payload signature])

        config           {:issuers {issuer {:alg        :RS256
                                            :public-key public-key}}}
        req              {:headers {"Authorization" (str "Bearer " tampered-token)}}]
    (let [handler (wrap-jwt (dummy-handler) {:issuers {issuer {:alg        :RS256
                                                               :public-key public-key}}})
          {:keys [body status headers]} (handler req)]
      (is (= 401 status))
      (is (= "The Token's Signature resulted invalid when verified using the Algorithm: SHA256withRSA" body))
      (is (nil? headers)))

    (let [handler (wrap-jwt (dummy-handler)
                            (assoc config :oauth-error-support {:enabled? true}))
          {:keys [status headers]} (handler req)]
      (is (= 401 status))
      (is (= "Bearer error=\"invalid_token\"" (:WWW-Authenticate headers))))))

(deftest expired-jwt-token-causes-401
  (let [{:keys [private-key public-key]} (util/generate-key-pair :RS256)
        issuer (str (UUID/randomUUID))
        claims {:iss issuer
                :exp (-> (now-to-seconds-accuracy)
                         (.minusSeconds 1)
                         (instant->date))}
        config {:issuers {issuer {:alg        :RS256
                                  :public-key public-key}}}
        req    (build-request claims {:alg         :RS256
                                      :private-key private-key})]
    (let [handler (wrap-jwt (dummy-handler) config)
          {:keys [body status headers]} (handler req)]
      (is (= 401 status))
      (is (clojure.string/starts-with? body "The Token has expired on"))
      (is (nil? headers))

      (let [respond #(assoc %1 :responded? true)
            {:keys [responded? status]} (handler req respond)]
        (is (= 401 status))
        (is (true? responded?))))

    (let [handler (wrap-jwt (dummy-handler)
                            (assoc config :oauth-error-support {:enabled? true}))
          {:keys [status headers]} (handler req)]
      (is (= 401 status))
      (is (= "Bearer error=\"invalid_token\"" (:WWW-Authenticate headers))))))

(deftest future-active-jwt-token-causes-401
  (let [{:keys [private-key public-key]} (util/generate-key-pair :RS256)
        issuer (str (UUID/randomUUID))
        claims {:iss issuer
                :nbf (-> (now-to-seconds-accuracy)
                         (.plusSeconds 1)
                         (instant->date))}
        config {:issuers {issuer {:alg        :RS256
                                  :public-key public-key}}}
        req    (build-request claims {:alg         :RS256
                                      :private-key private-key})]
    (let [handler (wrap-jwt (dummy-handler) config)
          {:keys [body status headers]} (handler req)]
      (is (= 401 status))
      (is (clojure.string/starts-with? body "The Token can't be used before"))
      (is (nil? headers))

      (let [respond #(assoc %1 :responded? true)
            {:keys [responded? status]} (handler req respond)]
        (is (= 401 status))
        (is (true? responded?))))

    (let [handler (wrap-jwt (dummy-handler)
                            (assoc config :oauth-error-support {:enabled? true}))
          {:keys [status headers]} (handler req)]
      (is (= 401 status))
      (is (= "Bearer error=\"invalid_token\"" (:WWW-Authenticate headers))))))

(deftest unknown-issuer-causes-401
  (let [issuer (str (UUID/randomUUID))
        claims {:a 1 :b 2 :iss "anotherissuer"}
        config {:issuers {issuer {:alg    :HS256
                                  :secret "whatever"}}}
        req    (build-request claims {:alg :HS256 :secret "whatever"})]
    (let [handler (wrap-jwt (dummy-handler) config)
          {:keys [status body headers]} (handler req)]
      (is (= 401 status))
      (is (= "Unknown issuer." body))
      (is (nil? headers))

      (let [respond #(assoc %1 :responded? true)
            {:keys [responded? status]} (handler req respond)]
        (is (= 401 status))
        (is (true? responded?))))

    (let [handler (wrap-jwt (dummy-handler)
                            (assoc config :oauth-error-support {:enabled? true}))
          {:keys [status headers]} (handler req)]
      (is (= 401 status))
      (is (= "Bearer error=\"invalid_token\"" (:WWW-Authenticate headers))))))

(deftest issuer-is-case-sensitive
  (let [issuer "someissuer"
        claims {:a 1 :b 2 :iss (clojure.string/upper-case issuer)}
        config {:issuers {issuer {:alg    :HS256
                                  :secret "whatever"}}}
        req    (build-request claims {:alg :HS256 :secret "whatever"})]
    (let [handler (wrap-jwt (dummy-handler) config)
          {:keys [status body headers]} (handler req)]
      (is (= 401 status))
      (is (= "Unknown issuer." body))
      (is (nil? headers)))

    (let [handler (wrap-jwt (dummy-handler)
                            (assoc config :oauth-error-support {:enabled? true}))
          {:keys [status headers]} (handler req)]
      (is (= 401 status))
      (is (= "Bearer error=\"invalid_token\"" (:WWW-Authenticate headers))))))

(deftest missing-token-causes-401-by-default
  (let [{:keys [public-key]} (util/generate-key-pair :RS256)
        issuer (str (UUID/randomUUID))
        config {:issuers {issuer {:alg        :RS256
                                  :public-key public-key}}}
        req    {}]
    (let [handler (wrap-jwt (fn [_] {:status 200}) config)
          {:keys [status headers]} (handler req)]
      (is (= 401 status))
      (is (nil? headers))

      (let [respond #(assoc %1 :responded? true)
            {:keys [responded? status]} (handler req respond)]
        (is (= 401 status))
        (is (true? responded?))))

    (let [handler (wrap-jwt (fn [_] {:status 200})
                            (assoc config :oauth-error-support {:enabled? true}))
          {:keys [status headers]} (handler req)]
      (is (= 401 status))
      (is (= "Bearer error=\"invalid_token\"" (:WWW-Authenticate headers))))))

(deftest missing-token-causes-401-if-configured-to-reject-missing-tokens
  (let [{:keys [public-key]} (util/generate-key-pair :RS256)
        issuer (str (UUID/randomUUID))
        config {:issuers               {issuer {:alg        :RS256
                                                :public-key public-key}}
                :reject-missing-token? true}
        req    {}]
    (let [handler (wrap-jwt (fn [_] {:status 200}) config)
          {:keys [status headers]} (handler req)]
      (is (= 401 status))
      (is (nil? headers)))

    (let [handler (wrap-jwt (fn [_] {:status 200})
                            (assoc config :oauth-error-support {:enabled? true}))
          {:keys [status headers]} (handler req)]
      (is (= 401 status))
      (is (= "Bearer error=\"invalid_token\"" (:WWW-Authenticate headers))))))

(deftest jwt-token-signed-with-no-iss-causes-failure-when-no-fallback-registered
  (let [{:keys [private-key]} (util/generate-key-pair :RS256)
        claims {:a 1 :b 2}
        config {:issuers {}}
        req    (build-request claims {:alg         :RS256
                                      :private-key private-key})]
    (let [handler (wrap-jwt (fn [_] {:status 200}) config)
          {:keys [status body headers]} (handler req)]
      (is (= 401 status))
      (is (= "Unknown issuer." body))
      (is (nil? headers)))

    (let [handler (wrap-jwt (fn [_] {:status 200})
                            (assoc config :oauth-error-support {:enabled? true}))
          {:keys [status headers]} (handler req)]
      (is (= 401 status))
      (is (= "Bearer error=\"invalid_token\"" (:WWW-Authenticate headers))))))

(deftest jwt-token-signed-by-unknown-issuer-is-not-ok-even-when-fallback-registered
  (let [{:keys [private-key public-key]} (util/generate-key-pair :RS256)
        claims {:a 1 :b 2 :iss (str (UUID/randomUUID))}
        config {:issuers {:no-issuer {:alg        :RS256
                                      :public-key public-key}}}
        req    (build-request claims {:alg         :RS256
                                      :private-key private-key})]
    (let [handler (wrap-jwt (fn [_] {:status 200}) config)
          {:keys [status body headers]} (handler req)]
      (is (= 401 status))
      (is (= "Unknown issuer." body))
      (is (nil? headers)))

    (let [handler (wrap-jwt (fn [_] {:status 200})
                            (assoc config :oauth-error-support {:enabled? true}))
          {:keys [status headers]} (handler req)]
      (is (= 401 status))
      (is (= "Bearer error=\"invalid_token\"" (:WWW-Authenticate headers))))))

(deftest mismatching-audience-causes-401
  (let [{:keys [private-key public-key]} (util/generate-key-pair :RS256)
        issuer (str (UUID/randomUUID))
        claims {:a 1 :b 2 :iss issuer :aud "myaudience"}
        config {:issuers {issuer {:alg        :RS256
                                  :audience   "anotheraudience"
                                  :public-key public-key}}}
        req    (build-request claims {:alg         :RS256
                                      :private-key private-key})]
    (let [handler (wrap-jwt (dummy-handler) config)
          {:keys [status body headers]} (handler req)]
      (is (= 401 status))
      (is (= "The Claim 'aud' value doesn't contain the required audience." body))
      (is (nil? headers))

      (let [respond #(assoc %1 :responded? true)
            {:keys [responded? status]} (handler req respond)]
        (is (= 401 status))
        (is (true? responded?))))

    (let [handler (wrap-jwt (dummy-handler)
                            (assoc config :oauth-error-support {:enabled? true}))
          {:keys [status headers]} (handler req)]
      (is (= 401 status))
      (is (= "Bearer error=\"invalid_token\"" (:WWW-Authenticate headers))))))

(deftest realm-is-included-in-www-authenticate-response-header
  (let [{:keys [private-key]} (util/generate-key-pair :RS256)
        issuer (str (UUID/randomUUID))
        req    (build-request {} {:alg         :RS256
                                  :private-key private-key})
        config {:issuers {issuer {:alg    :HS256
                                  :secret (util/generate-hmac-secret)}}}
        handler (wrap-jwt (dummy-handler)
                          (assoc config :oauth-error-support {:enabled? true :realm "myrealm"}))
        {:keys [status headers]} (handler req)]
    (is (= 401 status))
    (is (= "Bearer realm=\"myrealm\",error=\"invalid_token\"" (:WWW-Authenticate headers)))))