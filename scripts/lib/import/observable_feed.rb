# frozen_string_literal: true

require 'digest'
require 'fileutils'
require 'json'
require 'net/http'
require 'time'
require 'uri'
require 'yaml'

SOURCE_POLICY = File.expand_path('../../../data/observable-source-policy.yml', __dir__).freeze

module ObservableFeed
  MAX_BYTES = 5 * 1024 * 1024
  MAX_RECORDS = 10_000

  def fetch_json(url, output:, manifest:, headers: {}, body: nil)
    uri = URI(url)
    request = body ? Net::HTTP::Post.new(uri) : Net::HTTP::Get.new(uri)
    request['User-Agent'] = 'ThreatActor.info observable importer'
    headers.each { |key, value| request[key] = value }
    request.body = body if body
    response = Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == 'https') { |http| http.request(request) }
    unless response.is_a?(Net::HTTPSuccess)
      raise response.code.to_i == 429 ? "rate limited by source (HTTP 429)" : "HTTP #{response.code} for #{url}"
    end
    raise "response exceeds #{MAX_BYTES} bytes" if response.body.bytesize > MAX_BYTES

    payload = JSON.parse(response.body)
    raise 'response must be a JSON object or array' unless payload.is_a?(Hash) || payload.is_a?(Array)
    FileUtils.mkdir_p(output)
    File.write(File.join(output, 'data.json'), JSON.pretty_generate(payload) + "\n")
    checksum = Digest::SHA256.hexdigest(response.body)
    manifest.merge!('retrieved_at' => Time.now.utc.iso8601, 'record_count' => Array(payload.is_a?(Hash) ? payload['data'] : payload).length,
                    'source_checksum_sha256' => checksum, 'data_file' => 'data.json', 'query_status' => 'ok')
    File.write(File.join(output, 'manifest.yml'), YAML.dump(manifest))
    puts "Fetched #{manifest['record_count']} records into #{output}"
  rescue JSON::ParserError => error
    raise "malformed JSON response: #{error.message}"
  end

  def process_snapshot(snapshot, report_path:, write: false, limit: nil)
    path = File.directory?(snapshot) ? File.join(snapshot, 'data.json') : snapshot
    validate_snapshot!(snapshot) if File.directory?(snapshot)
    payload = JSON.parse(File.read(path))
    rows = Array(payload.is_a?(Hash) ? payload['data'] : payload)
    total_rows = rows.length
    rows = rows.first(MAX_RECORDS)
    rows = rows.first(limit) if limit
    actors = ActorStore.load_all
    by_alias = Hash.new { |hash, key| hash[key] = [] }
    actors.each_with_index { |actor, index| ([actor['name']] + Array(actor['aliases'])).each { |name| by_alias[normalize(name)] << [actor, index] } }
    grouped = rows.filter_map { |row| normalize_record(row) }.group_by do |record|
      record['observable_type'] + ':' + record['observable']
    end
    records = grouped.map do |key, claims|
      record = claims.first
      hints = claims.map { |claim| claim['actor_hint'].to_s.strip }.reject(&:empty?).uniq
      matches = hints.flat_map { |hint| by_alias[normalize(hint)] }.uniq { |entry| entry[1] }
      conflict = hints.length > 1 || matches.length > 1
      match = conflict ? nil : (matches.one? ? matches.first : nil)
      record['duplicate_claims'] = claims.length
      record['conflicting_actor_claims'] = hints if conflict
      record['matched_actor'] = match&.first&.dig('name')
      record['attribution_status'] = if conflict
                                       'quarantined_conflicting_actor_claims'
                                     elsif match
                                       'explicit_actor_match'
                                     else
                                       'quarantined_no_defensible_actor_attribution'
                                     end
      record
    end
    records = records.first(MAX_RECORDS)
    report = { 'source' => source_key, 'snapshot' => snapshot, 'mode' => write ? 'report_only' : 'plan',
               'total_records' => total_rows, 'records' => records.length, 'deduplicated' => records.length,
               'matched' => records.count { |r| r['matched_actor'] },
               'unmatched' => records.count { |r| !r['matched_actor'] },
               'matched_actors' => records.count { |r| r['matched_actor'] },
               'quarantined' => records.count { |r| r['attribution_status'].start_with?('quarantined') },
               'records_detail' => records.first(500) }
    # Deferred sources are report-only until the source register is explicitly approved.
    write_matches(records, actors) if write && publication_allowed?
    if report_path
      FileUtils.mkdir_p(File.dirname(report_path))
      File.write(report_path, JSON.pretty_generate(report) + "\n")
    end
    puts "[#{source_key} #{write ? 'IMPORT' : 'PLAN'}] records=#{records.length} matched=#{report['matched_actors']} quarantined=#{report['quarantined']}"
  rescue JSON::ParserError, Psych::Exception => error
    raise "snapshot is malformed: #{error.message}"
  end

  private

  def publication_allowed?
    policy = YAML.safe_load(File.read(SOURCE_POLICY), permitted_classes: [], aliases: false)
    %w[publish_conditional publish_metadata_only publish_enrichment_only].include?(policy.fetch('sources').fetch(source_key).fetch('decision'))
  end

  def validate_snapshot!(snapshot)
    manifest_path = File.join(snapshot, 'manifest.yml')
    raise 'snapshot missing manifest.yml' unless File.file?(manifest_path)
    manifest = YAML.safe_load(File.read(manifest_path), permitted_classes: [], aliases: false)
    raise 'snapshot manifest must be a mapping' unless manifest.is_a?(Hash)
    data_file = manifest['data_file'].to_s
    data_file = 'data.json' if data_file.empty?
    data_path = File.join(snapshot, data_file)
    raise 'snapshot manifest data file is missing' unless File.file?(data_path)
    expected = manifest['source_checksum_sha256'].to_s
    expected = manifest['checksum_sha256'].to_s if expected.empty?
    raise 'snapshot manifest missing checksum' unless expected.match?(/\A[a-f0-9]{64}\z/i)
    raise 'snapshot checksum mismatch' unless Digest::SHA256.file(data_path).hexdigest.casecmp?(expected)
    status = (manifest['query_status'] || manifest['status']).to_s
    raise "snapshot source status is #{status}" unless status.empty? || %w[ok healthy].include?(status)
    retrieved = Time.parse(manifest.fetch('retrieved_at').to_s)
    max_age = YAML.safe_load(File.read(SOURCE_POLICY), permitted_classes: [], aliases: false).fetch('sources').fetch(source_key).fetch('max_age_days', 30).to_i
    raise 'snapshot is too old' if retrieved < Time.now.utc - (max_age * 86_400)
    license_status = manifest['license_status'].to_s.downcase
    raise 'snapshot terms are not approved' if license_status.match?(/verify|unknown|pending/)
  rescue Psych::Exception, KeyError, ArgumentError => error
    raise "snapshot validation failed: #{error.message}"
  end

  def normalize(value)
    value.to_s.downcase.gsub(/[^a-z0-9]/, '')
  end

  def write_matches(records, actors)
    grouped = records.select { |r| r['matched_actor'] }.group_by { |r| r['matched_actor'] }
    grouped.each_value do |items|
      actor = actors.find { |candidate| candidate['name'] == items.first['matched_actor'] }
      next unless actor
      actor['iocs'] ||= {}
      items.each do |item|
        key = item['observable_type'] == 'url' ? 'urls' : 'sha256_hashes'
        actor['iocs'][key] ||= []
        actor['iocs'][key] << item['observable'] unless actor['iocs'][key].include?(item['observable'])
      end
      actor['provenance'] ||= {}
      actor['provenance'][source_key] = { 'source_dataset_url' => source_url, 'source_retrieved_at' => Time.now.utc.iso8601,
                                          'records_merged' => items.length,
                                          'source_attribution' => attribution }
    end
    ActorStore.save_all(actors) unless grouped.empty?
  end
end
