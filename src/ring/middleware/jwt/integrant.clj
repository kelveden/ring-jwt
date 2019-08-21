(ns ring.middleware.jwt.integrant
  (:require [integrant.core :as ig]
            [ring.middleware.jwt :refer [wrap-jwt]]))

(defmethod ig/init-key ::jwt [_ {:keys [opts]}]
  (fn [handler]
    (-> handler
        (wrap-jwt opts))))

