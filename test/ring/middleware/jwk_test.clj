(ns ring.middleware.jwk-test
  (:require [clj-wiremock.core :as wmk]
            [clojure.test :refer :all]
            [ring.middleware.jwk :refer [rsa-key-provider]]
            [ring.middleware.jwt-test-utils :as util])
  (:import (java.util UUID)))

(def ^:private wiremock-port 3000)
(def ^:private alg :RS256)

(defn ^:private init-jwk-provider
  [& [headers]]
  (let [jwk-endpoint (format "/my/jwk/%s" (str (UUID/randomUUID)))
        jwk-url      (format "http://localhost:%s%s" wiremock-port jwk-endpoint)
        jwk-provider (rsa-key-provider jwk-url headers)]
    [jwk-endpoint jwk-provider]))

(deftest jwk-provider-can-be-used-to-get-public-key-from-remote-url
  (let [wiremock-port 3000
        [jwk-endpoint jwk-provider] (init-jwk-provider)
        {:keys [_ public-key]} (util/generate-key-pair alg)
        key-id        (str (UUID/randomUUID))]
    (wmk/with-wiremock
      [{:port wiremock-port}]
      (wmk/with-stubs
        [{:req [:GET jwk-endpoint] :res [200 {:body (util/generate-jwk-response key-id public-key)}]}]

        (let [key-result1 (.getPublicKeyById jwk-provider key-id)
              jwk-req     (:request (first (wmk/request-journal (wmk/server wiremock-port))))]
          (is (= 1 (count (wmk/request-journal (wmk/server wiremock-port)))))
          (is (= "application/json" (get-in jwk-req [:headers :Accept])))
          (is (= public-key key-result1)))))))

(deftest jwk-is-cached
  (let [[jwk-endpoint jwk-provider] (init-jwk-provider)
        {:keys [_ public-key]} (util/generate-key-pair alg)
        key-id        (str (UUID/randomUUID))]
    (wmk/with-wiremock
      [{:port wiremock-port}]
      (wmk/with-stubs
        [{:req [:GET jwk-endpoint] :res [200 {:body (util/generate-jwk-response key-id public-key)}]}]

        (let [key-result1 (.getPublicKeyById jwk-provider key-id)]
          (is (= 1 (count (wmk/request-journal (wmk/server wiremock-port)))))
          (is (= public-key key-result1)))

        (let [key-result2 (.getPublicKeyById jwk-provider key-id)]
          (is (= 1 (count (wmk/request-journal (wmk/server wiremock-port)))))
          (is (= public-key key-result2)))))))

(deftest can-add-headers-to-call-to-jwk-provider
  (let [extra-headers {:header1 (str (UUID/randomUUID))
                       :header2 (str (UUID/randomUUID))}
        [jwk-endpoint jwk-provider] (init-jwk-provider extra-headers)
        {:keys [_ public-key]} (util/generate-key-pair alg)
        key-id        (str (UUID/randomUUID))]
    (wmk/with-wiremock
      [{:port wiremock-port}]
      (wmk/with-stubs
        [{:req [:GET jwk-endpoint] :res [200 {:body (util/generate-jwk-response key-id public-key)}]}]

        (let [key-result1 (.getPublicKeyById jwk-provider key-id)
              jwk-req     (:request (first (wmk/request-journal (wmk/server wiremock-port))))]
          (is (= 1 (count (wmk/request-journal (wmk/server wiremock-port)))))
          (is (= "application/json" (get-in jwk-req [:headers :Accept])))
          (is (= (:header1 extra-headers) (get-in jwk-req [:headers :header1])))
          (is (= (:header2 extra-headers) (get-in jwk-req [:headers :header2])))
          (is (= public-key key-result1)))))))