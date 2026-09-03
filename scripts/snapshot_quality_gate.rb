#!/usr/bin/env ruby
# frozen_string_literal: true

require 'digest'
require 'fileutils'
require 'json'
require 'time'
require 'yaml'

# Validates fetched snapshots before an importer is allowed to plan or apply.
module SnapshotQualityGate
  class Rejected < StandardError
    attr_reader :diagnostics

    def initialize(diagnostics)
      @diagnostics = diagnostics
      super("snapshot quarantined: #{diagnostics['issues'].join('; ')}")
    end
  end

  DEFAULTS = {
    'min_records' => 1,
    'max_records' => 50_000,
    'allow_empty' => false,
    'data_file' => 'actors.json',
    'required_record_keys' => ['name']
  }.freeze

  SOURCE_RULES = {
    'unit42' => { 'min_records' => 1, 'max_records' => 500, 'allow_empty' => false },
    # Dragos can publish an empty catalog during a normal no-groups interval, but
    # the fetcher must explicitly classify that state in the manifest.
    'dragos' => { 'min_records' => 0, 'max_records' => 500, 'allow_empty' => true }
  }.freeze

  module_function

  def validate!(snapshot_dir, source:, report_path: nil)
    rules = DEFAULTS.merge(SOURCE_RULES.fetch(source.to_s, {}))
    diagnostics = {
      'source' => source.to_s,
      'snapshot' => snapshot_dir,
      'status' => 'accepted',
      'issues' => [],
      'record_count' => nil,
      'raw_files' => []
    }

    manifest_path = File.join(snapshot_dir, 'manifest.yml')
    data_path = File.join(snapshot_dir, rules['data_file'])
    unless File.file?(manifest_path)
      diagnostics['issues'] << 'missing manifest.yml'
    end
    unless File.file?(data_path)
      diagnostics['issues'] << "missing #{rules['data_file']}"
    end

    manifest = load_yaml(manifest_path, diagnostics)
    records = load_json(data_path)
    diagnostics['record_count'] = records.length if records.is_a?(Array)
    diagnostics['raw_files'] = Dir.glob(File.join(snapshot_dir, '**', '*')).select { |p| File.file?(p) }.sort.map { |p| p.delete_prefix("#{snapshot_dir}/") }

    if records.nil?
      diagnostics['issues'] << 'data file is not valid JSON'
    elsif !records.is_a?(Array)
      diagnostics['issues'] << 'data file must contain an array of records'
    else
      validate_records(records, rules, diagnostics)
    end

    validate_checksum(snapshot_dir, manifest, diagnostics)
    validate_detail_page_checksums(snapshot_dir, manifest, diagnostics)
    if diagnostics['record_count'] == 0
      empty_classified = manifest['source_empty'] == true && !manifest['empty_reason'].to_s.strip.empty?
      diagnostics['classification'] = empty_classified ? 'source_empty' : 'parser_empty'
      diagnostics['issues'] << 'zero records are not explicitly classified as source_empty' unless empty_classified && rules['allow_empty']
    end

    diagnostics['status'] = 'quarantined' unless diagnostics['issues'].empty?
    if diagnostics['status'] == 'accepted'
      write_report(report_path, diagnostics) if report_path
      return diagnostics
    end

    quarantine(snapshot_dir, source, diagnostics)
    write_report(report_path, diagnostics) if report_path
    raise Rejected, diagnostics
  end

  def validate_records(records, rules, diagnostics)
    count = records.length
    diagnostics['issues'] << "record count #{count} below minimum #{rules['min_records']}" if count < rules['min_records']
    diagnostics['issues'] << "record count #{count} exceeds maximum #{rules['max_records']}" if count > rules['max_records']
    records.each_with_index do |record, index|
      unless record.is_a?(Hash)
        diagnostics['issues'] << "record #{index} is not an object"
        next
      end
      rules['required_record_keys'].each do |key|
        diagnostics['issues'] << "record #{index} missing #{key}" if record[key].to_s.strip.empty?
      end
      name = record['name'].to_s.strip
      if name.length > 120 || name.match?(/[.!?]\s|\b(?:the|this|group|actor|threat)\b.*\b(?:is|are|has|with)\b/i)
        diagnostics['issues'] << "record #{index} looks like prose parser output"
      end
    end
  end

  def validate_checksum(snapshot_dir, manifest, diagnostics)
    expected = manifest['source_checksum_sha256'].to_s
    diagnostics['issues'] << 'manifest missing source_checksum_sha256' if expected.empty?
    return if expected.empty?

    raw_name = if File.file?(File.join(snapshot_dir, 'page.html'))
                 'page.html'
               elsif File.file?(File.join(snapshot_dir, 'index.html'))
                 'index.html'
               end
    if raw_name.nil?
      diagnostics['issues'] << 'manifest checksum has no raw source file'
      return
    end
    actual = Digest::SHA256.file(File.join(snapshot_dir, raw_name)).hexdigest
    diagnostics['checksum'] = { 'file' => raw_name, 'expected' => expected, 'actual' => actual }
    diagnostics['issues'] << "checksum mismatch for #{raw_name}" unless actual == expected
  end

  def validate_detail_page_checksums(snapshot_dir, manifest, diagnostics)
    pages = manifest['detail_pages']
    return if pages.nil?
    unless pages.is_a?(Array)
      diagnostics['issues'] << "manifest detail_pages must be an array, got #{pages.class}"
      return
    end

    pages.each_with_index do |page, index|
      unless page.is_a?(Hash)
        diagnostics['issues'] << "detail page #{index} must be a mapping"
        next
      end
      file = page['file'].to_s
      expected = page['sha256'].to_s
      if file.empty? || expected.empty?
        diagnostics['issues'] << "detail page #{index} is missing file or sha256"
        next
      end
      root = File.expand_path(snapshot_dir)
      path = File.expand_path(file, root)
      unless path.start_with?(root + File::SEPARATOR) && File.file?(path)
        diagnostics['issues'] << "detail page #{index} file is missing or escapes snapshot"
        next
      end
      actual = Digest::SHA256.file(path).hexdigest
      diagnostics['issues'] << "checksum mismatch for #{file}" unless actual == expected
    end
  end

  def load_yaml(path, diagnostics)
    return {} unless File.file?(path)
    value = YAML.safe_load(File.read(path), permitted_classes: [Time], aliases: false)
    unless value.is_a?(Hash)
      diagnostics['issues'] << "manifest must contain a mapping, got #{value.class}"
      return {}
    end
    value
  rescue Psych::Exception => error
    diagnostics['issues'] << "manifest is invalid YAML: #{error.message.lines.first.to_s.strip}"
    {}
  end

  def load_json(path)
    return nil unless File.file?(path)
    JSON.parse(File.read(path))
  rescue JSON::ParserError
    nil
  end

  def write_report(path, diagnostics)
    FileUtils.mkdir_p(File.dirname(path))
    File.write(path, JSON.pretty_generate(diagnostics) + "\n")
  end

  def quarantine(snapshot_dir, source, diagnostics)
    root = File.join('tmp', 'snapshot-quarantine', source.to_s, Time.now.utc.strftime('%Y%m%dT%H%M%SZ'))
    diagnostics['quarantine_path'] = root
    FileUtils.mkdir_p(root)
    FileUtils.cp_r(File.join(snapshot_dir, '.'), root)
    write_report(File.join(root, 'diagnostics.json'), diagnostics)
  end
end
