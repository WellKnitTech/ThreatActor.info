#!/bin/bash

set -euo pipefail

echo "Starting ThreatActor.info validation pipeline..."
echo "=================================================="

check_command() {
  local command_name="$1"

  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "Missing required command: $command_name"
    exit 1
  fi
}

check_file() {
  local file_path="$1"

  if [ ! -f "$file_path" ]; then
    echo "Missing required file: $file_path"
    exit 1
  fi
}

check_dir() {
  local dir_path="$1"

  if [ ! -d "$dir_path" ]; then
    echo "Missing required directory: $dir_path"
    exit 1
  fi
}

check_command ruby
check_command bundle

check_dir "_data/actors"
check_file "_config.yml"
check_file "scripts/generate-pages.rb"
check_file "scripts/generate-indexes.rb"
check_file "scripts/evaluate-source-deltas.rb"
check_file "scripts/validate-content.rb"
check_file "scripts/validate-json-schemas.rb"

echo "Running page and index generators..."
echo "(Indexes are regenerated here so _data/generated/ and api/ stay aligned before validation and build.)"
ruby scripts/generate-pages.rb --force
ruby scripts/generate-indexes.rb

echo "Running JSON Schema validator..."
ruby scripts/validate-json-schemas.rb

echo "Running content validator..."
ruby scripts/validate-content.rb

echo "Running Jekyll doctor..."
if ! bundle exec jekyll doctor; then
  echo "Jekyll doctor reported warnings; continuing with build verification..."
fi

echo "Building site in safe mode..."
bundle exec jekyll build --safe

echo "Validating built API payloads..."
ruby -e "require 'json'; Dir.glob('_site/api/**/*.json').each { |path| JSON.parse(File.read(path)) }"

echo "Validation pipeline completed successfully."
echo "=================================================="
