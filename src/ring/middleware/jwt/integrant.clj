(ns ring.middleware.jwt.integrant
  (:require [integrant.core :as ig]
            [ring.middleware.jwt :refer [wrap-jwt]]))

(defmethod ig/init-key :ring.middleware.jwt/jwt [_ opts]
  (fn [handler]
    (-> handler
        (wrap-jwt opts))))

