#!/usr/bin/env ruby
# frozen_string_literal: true

require 'digest'
require 'fileutils'
require 'json'
require 'tmpdir'
require 'yaml'
require_relative 'snapshot_quality_gate'

Dir.mktmpdir('snapshot-gate-test') do |root|
  empty = File.join(root, 'dragos-empty')
  FileUtils.mkdir_p(empty)
  raw = '<html><main>No threat groups currently listed</main></html>'
  File.write(File.join(empty, 'index.html'), raw)
  File.write(File.join(empty, 'actors.json'), "[]\n")
  File.write(File.join(empty, 'manifest.yml'), YAML.dump(
    'source_checksum_sha256' => Digest::SHA256.hexdigest(raw),
    'source_empty' => true,
    'empty_reason' => 'upstream catalog contains no threat-group profiles'
  ))
  result = SnapshotQualityGate.validate!(empty, source: 'dragos')
  abort 'legitimate Dragos empty source was rejected' unless result['classification'] == 'source_empty'

  prose = File.join(root, 'unit42-prose')
  FileUtils.mkdir_p(prose)
  page = '<html><main>changed layout</main></html>'
  File.write(File.join(prose, 'page.html'), page)
  File.write(File.join(prose, 'actors.json'), JSON.dump([{ 'name' => 'This threat actor is described in a paragraph with unrelated prose.' }]))
  File.write(File.join(prose, 'manifest.yml'), YAML.dump('source_checksum_sha256' => Digest::SHA256.hexdigest(page)))
  begin
    SnapshotQualityGate.validate!(prose, source: 'unit42')
    abort 'prose-like Unit 42 output was accepted'
  rescue SnapshotQualityGate::Rejected => error
    abort 'diagnostics did not identify prose output' unless error.diagnostics['issues'].any? { |issue| issue.include?('prose') }
    abort 'raw snapshot was not quarantined' unless File.directory?(error.diagnostics['quarantine_path'])
  end

  corrupt = File.join(root, 'checksum')
  FileUtils.mkdir_p(corrupt)
  File.write(File.join(corrupt, 'page.html'), 'raw')
  File.write(File.join(corrupt, 'actors.json'), JSON.dump([{ 'name' => 'APT 1' }]))
  File.write(File.join(corrupt, 'manifest.yml'), YAML.dump('source_checksum_sha256' => '0' * 64))
  begin
    SnapshotQualityGate.validate!(corrupt, source: 'unit42')
    abort 'checksum mismatch was accepted'
  rescue SnapshotQualityGate::Rejected => error
    abort 'checksum diagnostic missing' unless error.diagnostics['issues'].any? { |issue| issue.include?('checksum mismatch') }
  end
end

puts 'snapshot quality gate tests passed'
