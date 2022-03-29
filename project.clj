(defproject net.clojars.kelveden/ring-jwt "2.3.1"
  :description "JWT middleware for Ring"
  :url "http://github.com/kelveden/ring-jwt"
  :license {:name "Eclipse Public License"
            :url  "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[cheshire "5.10.2"]
                 [commons-codec "1.15"]
                 [org.clojure/clojure "1.11.0"]
                 [com.auth0/java-jwt "3.19.0"]
                 [com.auth0/jwks-rsa "0.21.0"]]
  :profiles {:dev      {:dependencies [[org.clojure/test.check "1.1.1"]
                                       [kelveden/clj-wiremock "1.8.0"]
                                       [org.slf4j/slf4j-simple "1.7.36"]]
                        :eftest       {:multithread? false}
                        :plugins      [[lein-eftest "0.4.3"]]}})
