(defproject ovotech/ring-jwt "1.2.5"
  :description "JWT middleware for Ring"
  :url "http://github.com/ovotech/ring-jwt"
  :license {:name "Eclipse Public License"
            :url  "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[cheshire "5.9.0"]
                 [commons-codec "1.13"]
                 [org.clojure/clojure "1.10.1"]
                 [com.auth0/java-jwt "3.8.2"]
                 [com.auth0/jwks-rsa "0.8.3"]
                 [fipp "0.6.18"]]
  :profiles {:dev      {:dependencies [[org.clojure/test.check "1.0.0"]
                                       [kelveden/clj-wiremock "1.5.2"]
                                       [org.slf4j/slf4j-simple "1.7.30"]]
                        :eftest       {:multithread? false}
                        :plugins      [[lein-eftest "0.4.3"]]}})
