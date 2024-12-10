(defproject net.clojars.kelveden/ring-jwt "2.10.0"
  :description "JWT middleware for Ring"
  :url "http://github.com/kelveden/ring-jwt"
  :license {:name "Eclipse Public License"
            :url  "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[cheshire "5.13.0"]
                 [commons-codec "1.17.1"]
                 [org.clojure/clojure "1.12.0"]
                 [com.auth0/java-jwt "4.4.0"]
                 [com.auth0/jwks-rsa "0.22.1"]]
  :profiles {:dev      {:dependencies [[org.clojure/test.check "1.1.1"]
                                       [kelveden/clj-wiremock "1.8.0"]
                                       [org.slf4j/slf4j-simple "2.0.16"]]
                        :eftest       {:multithread? false}
                        :plugins      [[lein-eftest "0.4.3"]]}})
