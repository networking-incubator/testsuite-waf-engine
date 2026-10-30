# Web Application Firewall Engine Test Suite

Set of verification requests for Web Application Firewall.

Tests are split by what a failure means:

- `tests/rules` - CRS detection coverage; a failure is a ruleset or tuning problem.
- `tests/engine` - WAF connector behavior; a failure is an engine problem.

## Running locally

Needs [uv](https://docs.astral.sh/uv/). `GATEWAY_URL` points at a deployed
gateway, `HEADERS` adds a header to every request:

```sh
make test GATEWAY_URL=http://172.18.255.127
make test-attack GATEWAY_URL=http://gateway:10000 HEADERS="--header 'Host: waf.example.com'"
```

Other targets: `test-true` (legitimate traffic), `test-rules`, `test-engine`.

Multipart requests currently panic the engine's Wasm VM and degrade the
gateway for later requests, so they are excluded by default and run on their
own with `make test-multipart`.

## Linting

[ruff](https://docs.astral.sh/ruff/) handles both linting and formatting, and
needs no gateway:

```sh
make lint        # report problems
make lint-fix    # fix what is auto-fixable
make format      # rewrite files
make check       # lint + format --check, what CI runs
```

## Running from an image

```sh
make image
make image-test GATEWAY_URL=http://gateway:10000
```

Each `image-*` target mirrors its local counterpart and writes `junit.xml`
and `report.html` to `./reports` (override with `REPORT_DIR`). `GATEWAY_URL`
must be reachable from inside the container - for a gateway on the host, pass
a routable address or `RUN_FLAGS=--network=host`. Set `CONTAINER_ENGINE=docker`
to build with docker instead of podman; `make image-clean` removes the image
and the reports.

The image can also be run directly, with extra arguments passed to pytest.
Reports stay in `/app/reports` inside the container, so the make targets are
the easier way to get them out:

```sh
podman run --rm -e GATEWAY_URL=http://gateway:10000 \
    waf-engine-testsuite -m attack -v
```

## Published images

Images live in `quay.io/waf/testsuite-waf-engine`:

- `latest`, `1.2.3`, `1.2`, `1` - cut from a `v#.#.#` tag.
- `devel`, `main-<sha>` - the tip of main, rebuilt on every merge.

Both are published only after lint and the image smoke test pass. To release:

```sh
git tag v1.2.3 && git push origin v1.2.3
```
