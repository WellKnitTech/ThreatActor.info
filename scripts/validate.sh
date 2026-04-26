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

check_command ruby
check_command bundle

check_file "_data/threat_actors.yml"
check_file "_config.yml"
check_file "scripts/generate-indexes.rb"
check_file "scripts/validate-content.rb"

echo "Running index generator..."
ruby scripts/generate-indexes.rb

echo "Running content validator..."
ruby scripts/validate-content.rb

echo "Running Jekyll doctor..."
if ! bundle exec jekyll doctor; then
  echo "Jekyll doctor reported warnings; continuing with build verification..."
fi

echo "Building site in safe mode..."
bundle exec jekyll build --safe

echo "Validating built API payloads..."
ruby -e "require 'json'; %w[_site/api/threat-actors.json _site/api/iocs.json _site/api/facets.json _site/api/campaigns.json _site/api/malware.json _site/api/attack-mappings.json _site/api/references.json _site/api/ioc-lookup.json _site/api/ioc-types.json].each { |path| JSON.parse(File.read(path)) }; Dir.glob('_site/api/iocs/by-type/*.json').each { |path| JSON.parse(File.read(path)) }"

echo "Validation pipeline completed successfully."
echo "=================================================="
