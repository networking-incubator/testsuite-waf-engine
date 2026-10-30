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


# --- linting -----------------------------------------------------------
# Needs no gateway. `check` is what CI runs; it never rewrites a file.
.PHONY: lint
lint: uv-env
	uv run ruff check .

.PHONY: lint-fix
lint-fix: uv-env
	uv run ruff check --fix .

.PHONY: format
format: uv-env
	uv run ruff format .

.PHONY: check
check: uv-env
	uv run ruff check .
	uv run ruff format --check .

.PHONY: test-true
test-true: uv-env
	$(PYTEST) -m normal

.PHONY: test-attack
test-attack: uv-env
	$(PYTEST) -m attack

# CRS detection coverage - a failure here is a ruleset or tuning problem.
.PHONY: test-rules
test-rules: uv-env
	$(PYTEST) -m rules

# WAF connector behavior - a failure here is an engine problem.
.PHONY: test-engine
test-engine: uv-env
	$(PYTEST) -m engine

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
image: image-build image-smoke

.PHONY: image-build
image-build:
	$(CONTAINER_ENGINE) build -t $(IMAGE):$(IMAGE_TAG) .

# Run the image with whatever is in ARGS. The image-* targets below are the
# useful presets; this one is for anything else, including the smoke test.
.PHONY: image-run
image-run:
	$(call run-image,$(ARGS))

# Directory the smoke test copies its reports into, so a real run's reports
# in REPORT_DIR are left alone.
SMOKE_REPORT_DIR := $(CURDIR)/.smoke-reports

# The same checks CI runs on a pull request. No gateway needed: collection
# still exercises the entrypoint, the pytest config and every test import.
.PHONY: image-smoke
image-smoke:
	@echo "smoke: collecting tests, and writing reports, inside the image"
	@$(MAKE) --no-print-directory image-run \
		GATEWAY_URL=http://gateway.invalid HEADERS= ARGS="--collect-only -q" \
		CONTAINER_NAME=$(CONTAINER_NAME)-smoke REPORT_DIR=$(SMOKE_REPORT_DIR)
	@test -s $(SMOKE_REPORT_DIR)/junit.xml
	@test -s $(SMOKE_REPORT_DIR)/report.html
	@rm -rf $(SMOKE_REPORT_DIR)
	@echo "smoke: run without a gateway is refused"
	@if $(CONTAINER_ENGINE) run --rm -e GATEWAY_URL= $(IMAGE):$(IMAGE_TAG) -q \
		>/dev/null 2>&1; then \
		echo "entrypoint accepted an empty GATEWAY_URL" >&2; \
		exit 1; \
	fi
	@echo "smoke: ok"

.PHONY: image-test
image-test:
	$(call run-image,)

.PHONY: image-test-true
image-test-true:
	$(call run-image,-m normal)

.PHONY: image-test-attack
image-test-attack:
	$(call run-image,-m attack)

.PHONY: image-test-rules
image-test-rules:
	$(call run-image,-m rules)

.PHONY: image-test-engine
image-test-engine:
	$(call run-image,-m engine)

.PHONY: image-test-multipart
image-test-multipart:
	$(call run-image,-m multipart)

.PHONY: image-clean
image-clean:
	-$(CONTAINER_ENGINE) rm -f $(CONTAINER_NAME) 2>/dev/null
	-$(CONTAINER_ENGINE) rmi $(IMAGE):$(IMAGE_TAG) 2>/dev/null
	rm -rf $(REPORT_DIR)




