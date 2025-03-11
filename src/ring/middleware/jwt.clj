(ns ring.middleware.jwt
  (:require [clojure.spec.alpha :as s]
            [ring.middleware.token :as token])
  (:import (com.auth0.jwt.exceptions JWTVerificationException)))

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

(defn- handle-authn-error
  [responder message {:keys [oauth-error-support]}]
  (let [default-www-authenticate-values
        "error=\"invalid_token\""

        resp
        (cond-> {:status 401
                 :body   message}

          (:enabled? oauth-error-support)
          (assoc :headers {:WWW-Authenticate (str "Bearer " (if (:realm oauth-error-support)
                                                              (format "realm=\"%s\",%s" (:realm oauth-error-support)
                                                                      default-www-authenticate-values)
                                                              default-www-authenticate-values))}))]
    (responder resp)))

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

  (fn [{:keys [uri] :as req} & [respond raise]]
    (let [async?         (some? respond)
          invoke-handler (if async?
                           #(handler %1 respond raise)
                           #(handler %1))
          responder      (if async? #(respond %1) identity)]
      (if (contains? ignore-paths uri)
        ; Just disregard any token or whether it's even included in the request
        (invoke-handler req)

        ; Verify token and parse claims
        (try
          (if-let [token ((or find-token-fn (read-token-from-header "Authorization")) req)]
            (if-let [alg-opts (get issuers (or (token/decode-issuer token) :no-issuer))]
              (->> (token/decode token alg-opts)
                   (assoc req :claims)
                   (invoke-handler))
              (handle-authn-error responder "Unknown issuer." opts))

            (if reject-missing-token?
              (handle-authn-error responder "No token found." opts)
              (->> (assoc req :claims {})
                   (invoke-handler))))

          (catch JWTVerificationException e
            (handle-authn-error responder (ex-message e) opts)))))))

(s/fdef wrap-jwt
  :ret fn?
  :args (s/cat :handler fn?
               :opts ::opts))
