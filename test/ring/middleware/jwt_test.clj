(ns ring.middleware.jwt-test
  (:require [cheshire.core :as json]
            [clojure.string :refer [split join]]
            [clojure.test :refer :all]
            [ring.middleware.test.encode-utils :as eu]
            [ring.middleware.jwt :refer [wrap-jwt]])
  (:import (clojure.lang ExceptionInfo)))

(def ^:private dummy-handler (constantly identity))

(defn- build-request
  [token]
  {:some "data" :headers {"Authorization" (str "Bearer " token)}})

(defn- epoch-seconds
  []
  (int (/ (System/currentTimeMillis) 1000)))

(deftest claims-from-valid-jwt-token-in-authorization-header-are-added-to-request
  (let [{:keys [private-key public-key]} (eu/generate-key-pair :RS256)
        claims  {:a 1 :b 2}
        token   (eu/encode-token claims {:alg         :RS256
                                         :private-key private-key})
        handler (wrap-jwt (dummy-handler) {:alg        :RS256
                                           :public-key public-key})
        req     (build-request token)
        res     (handler req)]
    (is (= claims (:claims res)))))

(deftest jwt-token-signed-with-wrong-algorithm-causes-401
  (let [{:keys [private-key]} (eu/generate-key-pair :RS256)
        claims  {:a 1 :b 2}
        token   (eu/encode-token claims {:alg         :RS256
                                         :private-key private-key})
        handler (wrap-jwt (dummy-handler) {:alg    :HS256
                                           :secret (eu/generate-hmac-secret)})
        req     (build-request token)
        {:keys [body status]} (handler req)]
    (is (= 401 status))
    (is (= "Signature could not be verified." body))))

(deftest jwt-token-with-tampered-header-causes-401
  (let [{:keys [private-key public-key]} (eu/generate-key-pair :RS256)
        claims          {:a 1 :b 2}
        token           (eu/encode-token claims {:alg         :RS256
                                                 :private-key private-key})
        [_ payload signature] (split token #"\.")
        tampered-header (eu/str->base64 (json/generate-string {:alg :RS256 :a 1}))
        tampered-token  (join "." [tampered-header payload signature])

        handler         (wrap-jwt (dummy-handler) {:alg        :RS256
                                                   :public-key public-key})
        req             (build-request tampered-token)
        {:keys [body status]} (handler req)]
    (is (= 401 status))
    (is (= "Signature could not be verified." body))))

(deftest jwt-token-with-tampered-payload-causes-401
  (let [{:keys [private-key public-key]} (eu/generate-key-pair :RS256)
        claims           {:a 1 :b 2}
        token            (eu/encode-token claims {:alg         :RS256
                                                  :private-key private-key})

        [header _ signature] (split token #"\.")
        tampered-payload (eu/str->base64 (json/generate-string {:a 1}))
        tampered-token   (join "." [header tampered-payload signature])

        handler          (wrap-jwt (dummy-handler) {:alg        :RS256
                                                    :public-key public-key})
        req              (build-request tampered-token)
        {:keys [body status]} (handler req)]
    (is (= 401 status))
    (is (= "Signature could not be verified." body))))

(deftest no-jwt-token-causes-empty-claims-map-added-to-request
  (let [handler (wrap-jwt (dummy-handler) {:alg :HS256 :secret "whatever"})
        req     {:some "data"}
        res     (handler req)]
    (is (= req (dissoc res :claims)))
    (is (= {} (:claims res)))))

(deftest expired-jwt-token-causes-401
  (let [{:keys [private-key public-key]} (eu/generate-key-pair :RS256)
        claims  {:exp (- (epoch-seconds) 1)}
        token   (eu/encode-token claims {:alg :RS256 :private-key private-key})
        handler (wrap-jwt (dummy-handler) {:alg :RS256 :public-key public-key})
        req     (build-request token)
        {:keys [body status]} (handler req)]
    (is (= 401 status))
    (is (= "Token has expired." body))))

(deftest future-active-jwt-token-causes-401
  (let [{:keys [private-key public-key]} (eu/generate-key-pair :RS256)
        claims  {:nbf (+ (epoch-seconds) 1)}
        token   (eu/encode-token claims {:alg :RS256 :private-key private-key})
        handler (wrap-jwt (dummy-handler) {:alg :RS256 :public-key public-key})
        req     (build-request token)
        {:keys [body status]} (handler req)]
    (is (= 401 status))
    (is (= "One or more claims were invalid." body))))

(deftest expired-jwt-token-within-specified-leeway-is-valid
  (let [{:keys [private-key public-key]} (eu/generate-key-pair :RS256)
        claims  {:exp (- (epoch-seconds) 100)}
        token   (eu/encode-token claims {:alg :RS256 :private-key private-key})
        handler (wrap-jwt (dummy-handler) {:alg :RS256 :public-key public-key :leeway-seconds 1000})
        req     (build-request token)
        res     (handler req)]
    (is (= claims (:claims res)))))

(deftest future-jwt-token-within-specified-leeway-is-valid
  (let [{:keys [private-key public-key]} (eu/generate-key-pair :RS256)
        claims  {:nbf (+ (epoch-seconds) 100)}
        token   (eu/encode-token claims {:alg :RS256 :private-key private-key})
        handler (wrap-jwt (dummy-handler) {:alg :RS256 :public-key public-key :leeway-seconds 1000})
        req     (build-request token)
        res     (handler req)]
    (is (= claims (:claims res)))))

(deftest attempting-to-wrap-jwt-with-invalid-options-causes-error
  (is (thrown-with-msg? ExceptionInfo #"Invalid options."
        (wrap-jwt (dummy-handler) {:alg :HS256 :bollox "whatever"})))

  (is (thrown-with-msg? ExceptionInfo #"Invalid options."
                        (wrap-jwt (dummy-handler) {:alg :HS256 :secret 1})))

  (is (thrown-with-msg? ExceptionInfo #"Invalid options."
                        (wrap-jwt (dummy-handler) {:alg :RS256 :secret "whatever"}))))
