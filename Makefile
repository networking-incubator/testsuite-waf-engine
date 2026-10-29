GATEWAY_URL ?= http://localhost:10000/
# Extra headers for every request, e.g. HEADERS="--header 'Host: waf.example.com'"
HEADERS ?=

PYTEST:=uv run pytest --url $(GATEWAY_URL) $(HEADERS)


.PHONY: uv-env
uv-env:
	uv sync

.PHONY: test
test: uv-env
	$(PYTEST)

.PHONY: test-true
test-true: uv-env
	$(PYTEST) -m normal

.PHONY: test-attack
test-attack: uv-env
	$(PYTEST) -m 'attack'




