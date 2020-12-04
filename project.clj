(defproject ovotech/ring-jwt "2.0.1"
  :description "JWT middleware for Ring"
  :url "http://github.com/ovotech/ring-jwt"
  :license {:name "Eclipse Public License"
            :url  "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[cheshire "5.10.0"]
                 [commons-codec "1.14"]
                 [org.clojure/clojure "1.10.1"]
                 [com.auth0/java-jwt "3.10.3"]
                 [com.auth0/jwks-rsa "0.12.0"]]
  :profiles {:dev      {:dependencies [[org.clojure/test.check "1.1.0"]
                                       [kelveden/clj-wiremock "1.5.7"]
                                       [org.slf4j/slf4j-simple "1.7.30"]]
                        :eftest       {:multithread? false}
                        :plugins      [[lein-eftest "0.4.3"]]}})
