.PHONY: test

test:
	lein test

format:
	lein cljfmt fix

deploy:
	lein deploy clojars