(ns ring.middleware.encode-helper
  (:require [clojure.test :refer :all])
  (:import (com.auth0.jwt.algorithms Algorithm)
           (com.auth0.jwt JWT)))

(defn- encode-token*
  [algorithm claims]
  (-> (reduce (fn [acc [k v]]
                (.withClaim acc k v))
              (JWT/create)
              (clojure.walk/stringify-keys claims))
      (.sign algorithm)))

(defmulti encode-token
          "Encodes the given claims as a JWT using the given arguments as a basis."
          (fn [_ _ alg] alg))

(defmethod encode-token "RS256"
  [claims private-key _]
  (-> (Algorithm/RSA256 private-key)
      (encode-token* claims)))
