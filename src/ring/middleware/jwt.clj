(ns ring.middleware.jwt
  (:require [clojure.spec.alpha :as s]
            [ring.middleware.token :as token])
  (:import (com.auth0.jwt.exceptions SignatureVerificationException AlgorithmMismatchException JWTVerificationException TokenExpiredException)))

(defn read-token-from-header
  "Finds the token by searching the specified HTTP header (case-insensitive) for a bearer token."
  [header-name]
  (fn [{:keys [headers]}]
    (some->> headers
             (filter #(.equalsIgnoreCase header-name (key %)))
             (first)
             (val)
             (re-find #"(?i)^Bearer (.+)$")
             (last))))

(s/def ::alg-opts (s/and (s/keys :req-un [::token/alg]
                                 :opt-un [::token/leeway-seconds])
                         (s/or :secret-opts ::token/secret-opts
                               :public-key-opts ::token/public-key-opts)))
(s/def ::issuers (s/map-of ::token/issuer ::alg-opts))
(s/def ::find-token-fn fn?)
(s/def ::reject-missing-token? boolean?)

(s/def ::opts (s/keys :req-un [::issuers]
                      :opt-un [::find-token-fn ::reject-missing-token?]))

(defn wrap-jwt
  "Middleware that decodes a JWT token, verifies against the signature and then
  adds the decoded claims to the incoming request under :claims.

  If the JWT token exists but cannot be decoded then the token is considered tampered with and
  a 401 response is produced.

  If the JWT token does not exist, an empty :claims map is added to the incoming request."
  [handler {:keys [find-token-fn issuers reject-missing-token? ignore-paths]
            :or   {reject-missing-token? true
                   ignore-paths          #{}}
            :as   opts}]
  (when-not (s/valid? ::opts opts)
    (throw (ex-info "Invalid options." (s/explain-data ::opts opts))))

  (let [f (fn [{:keys [uri] :as req}]
            (if (contains? ignore-paths uri)
              ; Just disregard any token or whether it's even included in the request
               (handler req)

               ; Verify token and parse claims
               (try
                 (if-let [token ((or find-token-fn (read-token-from-header "Authorization")) req)]
                   (if-let [alg-opts (get issuers (or (token/decode-issuer token) :no-issuer))]
                     (->> (token/decode token alg-opts)
                          (assoc req :claims)
                          (handler))
                     {:status 401
                      :body   "Unknown issuer."})

                   (if reject-missing-token?
                     {:status 401
                      :body   "No token found."}
                     (->> (assoc req :claims {})
                          (handler))))

                 (catch JWTVerificationException e
                   {:status 401
                    :body   (ex-message e)}))))]
    (fn
      ([request]           (f request))
      ([request respond _] (respond (f request))))))

(s/fdef wrap-jwt
        :ret fn?
        :args (s/cat :handler fn?
                     :opts ::opts))
