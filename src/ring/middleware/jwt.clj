(ns ring.middleware.jwt
  (:require [ring.middleware.token :as token])
  (:import (com.auth0.jwt.exceptions SignatureVerificationException AlgorithmMismatchException)))

(defn- find-token
  [{:keys [headers]}]
  (some-> (get headers "Authorization")
          (clojure.string/split #" ")
          (last)))

(defn wrap-jwt
  "Middleware that decodes a JWT token, verifies against the signature and then
  adds the decoded claims to the incoming request under :claims.

  If the JWT token exists but cannot be decoded then the token is considered tampered with and
  a 401 response is produced.

  If the JWT token does not exist, an empty :claims map is added to the incoming request."
  [handler opts]
  (fn [req]
    (try
      (if-let [token (find-token req)]
        (->> (token/decode token opts)
             (assoc req :claims)
             (handler))
        (->> (assoc req :claims {})
             (handler)))

      (catch SignatureVerificationException _
        {:status 401})

      (catch AlgorithmMismatchException _
        {:status 401}))))