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

# An explicit -m replaces the default filter in pyproject.toml, so every
# selection below has to re-exclude multipart itself.
.PHONY: test-true
test-true: uv-env
	$(PYTEST) -m 'normal and not multipart'

.PHONY: test-attack
test-attack: uv-env
	$(PYTEST) -m 'attack and not multipart'

# CRS detection coverage - a failure here is a ruleset or tuning problem.
.PHONY: test-rules
test-rules: uv-env
	$(PYTEST) -m 'rules and not multipart'

# WAF connector behavior - a failure here is an engine problem.
.PHONY: test-engine
test-engine: uv-env
	$(PYTEST) -m 'engine and not multipart'

# Multipart currently panics the engine's Wasm VM and degrades the gateway
# for later requests, so it is opt-in and runs on its own.
.PHONY: test-multipart
test-multipart: uv-env
	$(PYTEST) -m multipart


# --- containerized suite -----------------------------------------------
# Run the same suite from an image against an already deployed gateway.
# GATEWAY_URL must be reachable from inside the container; for a gateway on
# the host, either use a routable address or RUN_FLAGS=--network=host.
CONTAINER_ENGINE ?= podman
IMAGE ?= waf-engine-testsuite
IMAGE_TAG ?= latest
CONTAINER_NAME ?= waf-engine-testsuite-run
# Reports (junit.xml, report.html) are copied here after each image run.
REPORT_DIR ?= $(CURDIR)/reports
# Extra flags for the container engine, e.g. RUN_FLAGS=--network=host
RUN_FLAGS ?=

# Run the image, copy the reports out, then propagate pytest's exit code.
# $(1) - extra pytest arguments
define run-image
	@set -e; \
	$(CONTAINER_ENGINE) rm -f $(CONTAINER_NAME) >/dev/null 2>&1 || true; \
	status=0; \
	$(CONTAINER_ENGINE) run --name $(CONTAINER_NAME) \
		-e GATEWAY_URL="$(GATEWAY_URL)" -e HEADERS="$(HEADERS)" \
		$(RUN_FLAGS) $(IMAGE):$(IMAGE_TAG) $(1) || status=$$?; \
	mkdir -p $(REPORT_DIR); \
	$(CONTAINER_ENGINE) cp $(CONTAINER_NAME):/app/reports/. $(REPORT_DIR)/ \
		|| echo "no reports to copy"; \
	$(CONTAINER_ENGINE) rm -f $(CONTAINER_NAME) >/dev/null; \
	echo "reports in $(REPORT_DIR)"; \
	exit $$status
endef

.PHONY: image
image:
	$(CONTAINER_ENGINE) build -t $(IMAGE):$(IMAGE_TAG) .

.PHONY: image-test
image-test:
	$(call run-image,)

.PHONY: image-test-true
image-test-true:
	$(call run-image,-m 'normal and not multipart')

.PHONY: image-test-attack
image-test-attack:
	$(call run-image,-m 'attack and not multipart')

.PHONY: image-test-rules
image-test-rules:
	$(call run-image,-m 'rules and not multipart')

.PHONY: image-test-engine
image-test-engine:
	$(call run-image,-m 'engine and not multipart')

.PHONY: image-test-multipart
image-test-multipart:
	$(call run-image,-m multipart)

.PHONY: image-clean
image-clean:
	-$(CONTAINER_ENGINE) rm -f $(CONTAINER_NAME) 2>/dev/null
	-$(CONTAINER_ENGINE) rmi $(IMAGE):$(IMAGE_TAG) 2>/dev/null
	rm -rf $(REPORT_DIR)




