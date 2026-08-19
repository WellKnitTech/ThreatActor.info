#!/usr/bin/env ruby
# frozen_string_literal: true

require 'digest'
require 'fileutils'
require 'json'
require 'net/http'
require 'optparse'
require 'open3'
require 'time'
require 'tmpdir'
require 'uri'
require 'yaml'

# Research-only extractor for the Orange Cyberdefense visual ransomware map.
# It never writes actor YAML and never copies the upstream PDF into publishable data.
class OcdRansomwareMapImporter
  SOURCE_KEY = 'ocd-ransomware-map'.freeze
  SOURCE_NAME = 'Orange Cyberdefense Ransomware Ecosystem Map'.freeze
  SOURCE_REPOSITORY = 'https://github.com/cert-orangecyberdefense/ransomware_map'.freeze
  SOURCE_COMMIT = '9f3715b623f7270bf1df13f2d10eb5dcd32bef1e'.freeze
  README_COMMIT = '37e580a5c18dfd59ef3eaa61cdbd44a9747ff472'.freeze
  README_URL = "https://raw.githubusercontent.com/cert-orangecyberdefense/ransomware_map/#{README_COMMIT}/README.md".freeze
  PDF_URL = "https://raw.githubusercontent.com/cert-orangecyberdefense/ransomware_map/#{SOURCE_COMMIT}/OCD_WorldWatch_Ransomware-ecosystem-map.pdf".freeze
  CLAIMED_VERSION = 29
  EXPECTED_PDF_SHA256 = 'af80618bd85dc6924bad6df24a6f9818eb658274fa4c5f75ef2bd3583e6fd4a1'.freeze
  EXPECTED_README_SHA256 = '8a56379c07c6ee10e25b4cbe827d3bddd9b5d03472695eb3824f57218f2e4ae4'.freeze
  MAX_DOWNLOAD_BYTES = 10 * 1024 * 1024
  TIMEOUT_SECONDS = 20
  LICENSE_MARKER = /all rights reserved/i

  def self.run!(argv)
    command = argv.shift
    options = { snapshot: nil, output: nil, pdf_url: PDF_URL, readme_url: README_URL }
    OptionParser.new do |parser|
      parser.on('--snapshot PATH') { |value| options[:snapshot] = value }
      parser.on('--output PATH') { |value| options[:output] = value }
      parser.on('--pdf-url URL') { |value| options[:pdf_url] = value }
      parser.on('--readme-url URL') { |value| options[:readme_url] = value }
    end.parse!(argv)

    case command
    when 'fetch'
      raise OptionParser::MissingArgument, '--output is required' unless options[:output]
      new(snapshot: options[:output], output: options[:output], pdf_url: options[:pdf_url],
          readme_url: options[:readme_url]).fetch
    when 'plan'
      raise OptionParser::MissingArgument, '--snapshot is required' unless options[:snapshot]
      report = new(snapshot: options[:snapshot], output: options[:output] || 'tmp/ocd-ransomware-map').plan
      puts JSON.pretty_generate(report)
      exit 1 if report['status'] == 'quarantined'
    else
      warn "Usage: ruby scripts/import-ocd-ransomware-map.rb fetch --output PATH | plan --snapshot PATH [--output PATH]"
      exit 1
    end
  end

  def initialize(snapshot:, output:, expected_pdf_sha256: EXPECTED_PDF_SHA256,
                 expected_readme_sha256: EXPECTED_README_SHA256, pdf_url: PDF_URL, readme_url: README_URL)
    @snapshot = snapshot
    @output = output
    @expected_pdf_sha256 = expected_pdf_sha256
    @expected_readme_sha256 = expected_readme_sha256
    @pdf_url = pdf_url
    @readme_url = readme_url
  end

  def fetch
    FileUtils.mkdir_p(@snapshot)
    pdf = bounded_get(URI.parse(@pdf_url))
    readme = bounded_get(URI.parse(@readme_url))
    verify_pdf_hash!(pdf)
    verify_readme!(readme)
    File.binwrite(File.join(@snapshot, 'source.pdf'), pdf)
    File.write(File.join(@snapshot, 'README.md'), readme)
    File.write(File.join(@snapshot, 'manifest.yml'), YAML.dump(manifest_for(pdf, readme)))
    { 'status' => 'accepted', 'snapshot' => @snapshot, 'pdf_sha256' => Digest::SHA256.hexdigest(pdf) }
  end

  def plan
    validate_output_path!
    FileUtils.mkdir_p(@output)
    diagnostics = []
    candidates = []
    extraction = {}
    begin
      manifest = load_manifest
      pdf = File.binread(File.join(@snapshot, 'source.pdf'))
      readme = File.read(File.join(@snapshot, 'README.md'))
      validate_manifest!(manifest)
      verify_pdf_hash!(pdf)
      verify_readme!(readme)
      raise 'snapshot PDF checksum metadata changed' unless manifest['pdf_sha256'] == Digest::SHA256.hexdigest(pdf)
      raise 'snapshot README checksum metadata changed' unless manifest['readme_sha256'] == Digest::SHA256.hexdigest(readme)
      extraction = extract_pdf(pdf)
      candidates, parser_diagnostics = parse_candidates(readme)
      diagnostics.concat(parser_diagnostics)
    rescue StandardError => error
      diagnostics << diagnostic(error.message.start_with?('PDF checksum') ? 'pdf_checksum_mismatch' : error_code(error.message), error.message)
    end

    quarantined = diagnostics.any? { |diagnostic| diagnostic['severity'] == 'error' }
    File.write(File.join(@output, 'candidates.json'), JSON.pretty_generate(candidates) + "\n") unless quarantined
    report = {
      'status' => quarantined ? 'quarantined' : (diagnostics.empty? ? 'accepted' : 'partial'),
      'source_key' => SOURCE_KEY,
      'source_name' => SOURCE_NAME,
      'source_repository' => SOURCE_REPOSITORY,
      'source_url' => @pdf_url,
      'source_commit' => SOURCE_COMMIT,
      'claimed_map_version' => CLAIMED_VERSION,
      'candidates' => quarantined ? [] : candidates,
      'diagnostics' => diagnostics,
      'extraction' => extraction,
      'manual_adjudication' => manual_adjudication
    }
    File.write(File.join(@output, 'report.json'), JSON.pretty_generate(report) + "\n")
    report
  end

  private

  def load_manifest
    path = File.join(@snapshot, 'manifest.yml')
    raise 'snapshot manifest is missing' unless File.file?(path)
    YAML.safe_load(File.read(path), permitted_classes: [Time], aliases: false) || {}
  rescue Psych::Exception => error
    raise "snapshot manifest is invalid: #{error.message}"
  end

  def validate_manifest!(manifest)
    raise 'snapshot source key changed' unless manifest['source_key'] == SOURCE_KEY
    raise 'snapshot version changed' unless manifest['claimed_map_version'].to_i == CLAIMED_VERSION
    raise 'snapshot PDF path changed' unless manifest['pdf_path'] == 'source.pdf'
    raise 'snapshot README path changed' unless manifest['readme_path'] == 'README.md'
    raise 'snapshot license verification failed' unless manifest['license_verified'] == true
  end

  def verify_pdf_hash!(pdf)
    raise "PDF checksum mismatch: expected #{@expected_pdf_sha256}" unless Digest::SHA256.hexdigest(pdf) == @expected_pdf_sha256
    raise 'PDF structure invalid: missing PDF header' unless pdf.start_with?('%PDF-')
    raise 'PDF exceeds configured size limit' if pdf.bytesize > MAX_DOWNLOAD_BYTES
  end

  def verify_readme!(readme)
    raise "README checksum mismatch: expected #{@expected_readme_sha256}" unless Digest::SHA256.hexdigest(readme) == @expected_readme_sha256
    raise 'source license verification failed' unless readme.match?(LICENSE_MARKER)
    raise "source version changed: expected #{CLAIMED_VERSION}" unless readme.match?(/Latest\s*=\s*version\s+#{CLAIMED_VERSION}\b/i)
  end

  def extract_pdf(pdf)
    Dir.mktmpdir('ocd-pdf') do |directory|
      input = File.join(directory, 'source.pdf')
      text_path = File.join(directory, 'extracted.txt')
      File.binwrite(input, pdf)
      command = ['pdftotext', '-layout', '-nopgbrk', input, text_path]
      _stdout, stderr, status = Open3.capture3(*command)
      raise "PDF structure invalid: #{stderr.strip}" unless status.success?
      text = normalize_text(File.read(text_path))
      { 'tool' => 'pdftotext', 'layout_mode' => 'layout', 'text_sha256' => Digest::SHA256.hexdigest(text),
        'text_bytes' => text.bytesize, 'page_count' => text.scan(/\f/).length + 1 }
    end
  end

  def parse_candidates(readme)
    diagnostics = []
    candidates = []
    readme.each_line.with_index(1) do |line, line_number|
      match = line.match(/\b(New addition|Edit):\s*(.*?)\s*$/i)
      next unless match
      event_type = match[1].casecmp('new addition').zero? ? 'New addition' : 'Edit'
      label = match[2].sub(/\s+-\s+[A-Z][a-z]+\s+\d{4}\s*$/, '').strip
      if label.empty?
        diagnostics << diagnostic('missing_label', "#{event_type} at README line #{line_number} has no label", severity: 'warning', location: line_number)
        next
      end
      if label.match?(/\s(?:\/|&|and)\s/i)
        diagnostics << diagnostic('ambiguous_label', "#{label.inspect} may contain multiple entities", severity: 'warning', location: line_number)
      end
      candidates << {
        'candidate_id' => "ocd-v#{CLAIMED_VERSION}-#{Digest::SHA256.hexdigest(label.downcase)[0, 12]}",
        'source_label' => label,
        'event_type' => event_type,
        'evidence_type' => 'source_changelog',
        'source_version' => CLAIMED_VERSION,
        'source_commit' => SOURCE_COMMIT,
        'needs_review' => true,
        'review_reasons' => ['entity type, alias equivalence, and relationship semantics are not machine-readable']
      }
    end
    [candidates.sort_by { |candidate| [candidate['event_type'], candidate['source_label'].downcase] }, diagnostics]
  end

  def manifest_for(pdf, readme)
    { 'source_key' => SOURCE_KEY, 'source_name' => SOURCE_NAME, 'source_url' => @pdf_url,
      'readme_url' => @readme_url, 'source_commit' => SOURCE_COMMIT, 'claimed_map_version' => CLAIMED_VERSION,
      'retrieved_at' => Time.now.utc.iso8601, 'pdf_path' => 'source.pdf', 'readme_path' => 'README.md',
      'pdf_sha256' => Digest::SHA256.hexdigest(pdf), 'readme_sha256' => Digest::SHA256.hexdigest(readme),
      'pdf_bytes' => pdf.bytesize, 'license_verified' => readme.match?(LICENSE_MARKER) }
  end

  def bounded_get(uri, redirects = 3)
    raise ArgumentError, 'source URL must use https' unless uri.is_a?(URI::HTTPS)
    raise ArgumentError, 'source host is not allowlisted' unless %w[raw.githubusercontent.com github.com].include?(uri.host)
    raise 'redirect limit exceeded' if redirects.zero?
    request = Net::HTTP::Get.new(uri)
    response = nil
    body = String.new
    Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == 'https',
                    open_timeout: TIMEOUT_SECONDS, read_timeout: TIMEOUT_SECONDS) do |http|
      http.request(request) do |candidate|
        response = candidate
        next unless candidate.is_a?(Net::HTTPSuccess)

        raise 'response exceeds configured size limit' if candidate['content-length'].to_i > MAX_DOWNLOAD_BYTES
        candidate.read_body do |chunk|
          body << chunk
          raise 'response exceeds configured size limit' if body.bytesize > MAX_DOWNLOAD_BYTES
        end
      end
    end
    return bounded_get(URI.parse(response['location']), redirects - 1) if response.is_a?(Net::HTTPRedirection)
    raise "HTTP #{response.code} from #{uri}" unless response.is_a?(Net::HTTPSuccess)
    body
  rescue Net::OpenTimeout, Net::ReadTimeout
    raise 'source download timed out'
  end

  def normalize_text(text)
    text.encode('UTF-8', invalid: :replace, undef: :replace, replace: '').gsub("\r\n", "\n").lines.map { |line| line.rstrip }.join
  end

  def validate_output_path!
    raise ArgumentError, 'output path traversal is not allowed' if @output.to_s.split(File::SEPARATOR).include?('..')
  end

  def diagnostic(code, message, severity: 'error', location: nil)
    { 'code' => code, 'message' => message, 'severity' => severity, 'location' => location }
  end

  def error_code(message)
    return 'pdf_structure_invalid' if message.start_with?('PDF structure invalid')
    return 'license_verification_failed' if message.include?('license')
    return 'source_format_changed' if message.include?('version') || message.include?('path')
    'snapshot_invalid'
  end

  def manual_adjudication
    ['Confirm family/operation/affiliate/malware entity type', 'Review aliases before merging',
     'Review all relationships and timeline placement', 'Accept candidates manually before any actor update']
  end
end

OcdRansomwareMapImporter.run!(ARGV) if $PROGRAM_NAME == __FILE__