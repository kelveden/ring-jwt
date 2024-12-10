(ns ring.middleware.test-utils
  (:require [ring.middleware.jwt-test-utils :refer [add-jwt-token]])
  (:import (java.time Instant)
           (java.util Date)))

(defn build-request
  [claims alg-opts]
  (add-jwt-token {} claims alg-opts))

(defn now-to-seconds-accuracy []
  (-> (Instant/now)
      (.getEpochSecond)
      (Instant/ofEpochSecond)))

(defn instant->date [instant]
  (Date/from instant))
