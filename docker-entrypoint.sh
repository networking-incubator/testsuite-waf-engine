#!/bin/sh
# Run the test suite against an already deployed gateway.
#
# GATEWAY_URL - base URL of the gateway, passed to pytest as --url
# HEADERS     - extra pytest arguments, word-split by the shell,
#               e.g. "--header 'Host: waf.example.com'"
# REPORT_DIR  - where junit.xml and report.html are written, /app/reports by
#               default. Set it to an empty value to skip report generation.
#
# Any arguments given to the container are appended to the pytest command.
# Passing --url as a container argument overrides GATEWAY_URL; passing
# --junitxml or --html skips the matching default report.
set -eu

if [ -z "${GATEWAY_URL:-}" ] && ! echo " $* " | grep -q -- " --url"; then
    echo "GATEWAY_URL is not set and no --url argument was given." >&2
    echo "Example: -e GATEWAY_URL=http://gateway:10000" >&2
    exit 2
fi

if [ -n "${HEADERS:-}" ]; then
    eval "set -- $HEADERS \"\$@\""
fi

report_dir="${REPORT_DIR-/app/reports}"
if [ -n "$report_dir" ]; then
    if ! mkdir -p "$report_dir" 2>/dev/null || [ ! -w "$report_dir" ]; then
        echo "Report directory $report_dir is not writable, skipping reports." >&2
        report_dir=""
    fi
fi

if [ -n "$report_dir" ]; then
    case " $* " in
        *" --junitxml"*) ;;
        *) set -- "--junitxml=$report_dir/junit.xml" "$@" ;;
    esac
    case " $* " in
        *" --html"*) ;;
        *) set -- "--html=$report_dir/report.html" --self-contained-html "$@" ;;
    esac
fi

if [ -n "${GATEWAY_URL:-}" ]; then
    set -- --url "$GATEWAY_URL" "$@"
fi

exec pytest "$@"
