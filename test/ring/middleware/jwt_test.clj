(ns ring.middleware.jwt-test
  (:require [clojure.test :refer :all]))

(deftest claims-from-valid-jwt-token-in-authorization-header-are-added-to-request)

(deftest jwt-token-with-undecodeable-header-causes-401)

(deftest jwt-token-with-unverifiable-payload-causes-401)

(deftest no-jwt-token-causes-empty-claims-map-added-to-request)