# Build the test suite into a runnable image:
#   podman build -t waf-engine-testsuite .
#   podman run --rm -e GATEWAY_URL=http://gateway:10000 waf-engine-testsuite
#
# Any extra arguments are passed straight to pytest:
#   podman run --rm -e GATEWAY_URL=http://gateway:10000 \
#       waf-engine-testsuite -m attack -v
#
# junit.xml and report.html are written to /app/reports; mount a volume
# there to collect them.

# Must match the runtime base: the venv carries musl-linked wheels, which a
# glibc image cannot load, and a Python of a different minor version cannot
# find at all.
FROM python:3.15-alpine AS builder
COPY --from=docker.io/astral/uv:latest /uv /uvx /bin/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /app

# Dependencies only, so the layer is reused when the tests change.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev


FROM python:3.15-alpine

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    GATEWAY_URL="" \
    REPORT_DIR=/app/reports

WORKDIR /app

COPY --from=builder /app/.venv /app/.venv
COPY pyproject.toml ./
COPY tests ./tests
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

# Reports land here; mount a volume over it to keep them. Group-writable so
# the suite still works when the platform picks an arbitrary UID.
RUN mkdir -p /app/reports && chown -R 1001:0 /app && chmod -R g=u /app \
    && chmod g+ws /app/reports

USER 1001

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD []
