.PHONY: authentik-up
authentik-up: ## Start authentik on kind
	hack/authentik/up.sh

.PHONY: authentik-down
authentik-down: ## Delete the kind cluster
	hack/authentik/down.sh

.PHONY: poc
poc: ## Verify the assumptions in docs/spec.md §8 against a running authentik
	hack/poc/verify.sh
