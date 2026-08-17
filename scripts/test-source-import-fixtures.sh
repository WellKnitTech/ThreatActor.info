#!/usr/bin/env bash
set -euo pipefail

# Offline-only contract suite; no source URL is contacted.
exec ruby -Itest test/source_import_fixture_contract_test.rb
