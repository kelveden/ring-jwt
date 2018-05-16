(ns ring.middleware.jwt-test
  (:require [cheshire.core :as json]
            [clojure.string :refer [split join]]
            [clojure.test :refer :all]
            [ring.middleware.encode-helper :as eh]
            [ring.middleware.jwt :refer [wrap-jwt]]))

(defn- dummy-handler [] (fn [x] x))
(def ^:private alg :RS256)

(defn- build-request
  [token]
  {:some "data" :headers {"Authorization" (str "Bearer " token)}})

(defn- epoch-seconds
  []
  (int (/ (System/currentTimeMillis) 1000)))

(deftest claims-from-valid-jwt-token-in-authorization-header-are-added-to-request
  (let [[private-key public-key] (eh/generate-rsa-key-pair)
        claims  {:a 1 :b 2}
        token   (eh/encode-token claims {:alg         alg
                                         :private-key private-key})
        handler (wrap-jwt (dummy-handler) {:alg        alg
                                           :public-key public-key})
        req     (build-request token)
        res     (handler req)]
    (is (= claims (:claims res)))))

(deftest jwt-token-signed-with-wrong-algorithm-causes-401
  (let [[private-key _] (eh/generate-rsa-key-pair)
        claims  {:a 1 :b 2}
        token   (eh/encode-token claims {:alg         :RS256
                                         :private-key private-key})
        handler (wrap-jwt (dummy-handler) {:alg    :HS256
                                           :secret (eh/generate-hmac-secret)})
        req     (build-request token)
        {:keys [body status]} (handler req)]
    (is (= 401 status))
    (is (= "Signature could not be verified." body))))

(deftest jwt-token-with-tampered-header-causes-401
  (let [[private-key public-key] (eh/generate-rsa-key-pair)
        claims          {:a 1 :b 2}
        token           (eh/encode-token claims {:alg         alg
                                                 :private-key private-key})
        [_ payload signature] (split token #"\.")
        tampered-header (eh/str->base64 (json/generate-string {:alg alg :a 1}))
        tampered-token  (join "." [tampered-header payload signature])

        handler         (wrap-jwt (dummy-handler) {:alg        alg
                                                   :public-key public-key})
        req             (build-request tampered-token)
        {:keys [body status]} (handler req)]
    (is (= 401 status))
    (is (= "Signature could not be verified." body))))

(deftest jwt-token-with-tampered-payload-causes-401
  (let [[private-key public-key] (eh/generate-rsa-key-pair)
        claims           {:a 1 :b 2}
        token            (eh/encode-token claims {:alg         alg
                                                  :private-key private-key})

        [header _ signature] (split token #"\.")
        tampered-payload (eh/str->base64 (json/generate-string {:a 1}))
        tampered-token   (join "." [header tampered-payload signature])

        handler          (wrap-jwt (dummy-handler) {:alg        alg
                                                    :public-key public-key})
        req              (build-request tampered-token)
        {:keys [body status]} (handler req)]
    (is (= 401 status))
    (is (= "Signature could not be verified." body))))

(deftest no-jwt-token-causes-empty-claims-map-added-to-request
  (let [handler (wrap-jwt (dummy-handler) {})
        req     {:some "data"}
        res     (handler req)]
    (is (= req (dissoc res :claims)))
    (is (= {} (:claims res)))))

(deftest expired-jwt-token-causes-401
  (let [[private-key public-key] (eh/generate-rsa-key-pair)
        claims  {:exp (- (epoch-seconds) 1)}
        token   (eh/encode-token claims {:alg alg :private-key private-key})
        handler (wrap-jwt (dummy-handler) {:alg alg :public-key public-key})
        req     (build-request token)
        {:keys [body status]} (handler req)]
    (is (= 401 status))
    (is (= "Token has expired." body))))

(deftest future-active-jwt-token-causes-401
  (let [[private-key public-key] (eh/generate-rsa-key-pair)
        claims  {:nbf (+ (epoch-seconds) 1)}
        token   (eh/encode-token claims {:alg alg :private-key private-key})
        handler (wrap-jwt (dummy-handler) {:alg alg :public-key public-key})
        req     (build-request token)
        {:keys [body status]} (handler req)]
    (is (= 401 status))
    (is (= "One or more claims were invalid." body))))

(deftest expired-jwt-token-within-specified-leeway-is-valid
  (let [[private-key public-key] (eh/generate-rsa-key-pair)
        claims  {:exp (- (epoch-seconds) 100)}
        token   (eh/encode-token claims {:alg alg :private-key private-key})
        handler (wrap-jwt (dummy-handler) {:alg alg :public-key public-key :leeway-seconds 1000})
        req     (build-request token)
        res     (handler req)]
    (is (= claims (:claims res)))))

(deftest future-jwt-token-within-specified-leeway-is-valid
  (let [[private-key public-key] (eh/generate-rsa-key-pair)
        claims  {:nbf (+ (epoch-seconds) 100)}
        token   (eh/encode-token claims {:alg alg :private-key private-key})
        handler (wrap-jwt (dummy-handler) {:alg alg :public-key public-key :leeway-seconds 1000})
        req     (build-request token)
        res     (handler req)]
    (is (= claims (:claims res)))))

(deftest token-signed-with-unsupported-cryptographic-algorith-causes-400
  (let [secret  "whatever"
        claims  {:a 1}
        token   (eh/encode-token claims {:alg :HS512 :secret secret})
        handler (wrap-jwt (dummy-handler) {:alg alg :secret secret})
        req     (build-request token)
        {:keys [body status]} (handler req)]
    (is (= 400 status))
    (is (= "One or more claims were invalid." body))))