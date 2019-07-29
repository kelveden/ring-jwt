(defproject ovotech/ring-jwt "1.2.1"
  :description "JWT middleware for Ring"
  :url "http://github.com/ovotech/ring-jwt"
  :license {:name "Eclipse Public License"
            :url  "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[cheshire "5.8.1"]
                 [commons-codec "1.12"]
                 [org.clojure/clojure "1.10.1"]
                 [com.auth0/java-jwt "3.8.1"]
                 [com.auth0/jwks-rsa "0.8.2"]
                 [fipp "0.6.18"]]
  :profiles {:dev {:dependencies [[org.clojure/test.check "0.9.0"]
                                  [kelveden/clj-wiremock "1.3.0"]]
                   :eftest       {:multithread? false}
                   :plugins      [[lein-eftest "0.4.3"]]}})
