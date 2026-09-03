# frozen_string_literal: true

require 'digest'
require 'fileutils'
require 'json'
require 'net/http'
require 'time'
require 'uri'
require 'yaml'

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
    manifest.merge!('retrieved_at' => Time.now.utc.iso8601, 'record_count' => Array(payload.is_a?(Hash) ? payload['data'] : payload).length,
                    'checksum_sha256' => Digest::SHA256.hexdigest(response.body), 'data_file' => 'data.json')
    File.write(File.join(output, 'manifest.yml'), YAML.dump(manifest))
    puts "Fetched #{manifest['record_count']} records into #{output}"
  rescue JSON::ParserError => error
    raise "malformed JSON response: #{error.message}"
  end

  def process_snapshot(snapshot, report_path:, write: false, limit: nil)
    path = File.directory?(snapshot) ? File.join(snapshot, 'data.json') : snapshot
    payload = JSON.parse(File.read(path))
    rows = Array(payload.is_a?(Hash) ? payload['data'] : payload)
    rows = rows.first(MAX_RECORDS)
    rows = rows.first(limit) if limit
    actors = ActorStore.load_all
    by_alias = Hash.new { |hash, key| hash[key] = [] }
    actors.each_with_index { |actor, index| ([actor['name']] + Array(actor['aliases'])).each { |name| by_alias[normalize(name)] << [actor, index] } }
    seen = {}
    records = rows.filter_map { |row| normalize_record(row) }.each_with_object([]) do |record, out|
      key = record['observable_type'] + ':' + record['observable']
      next if seen[key]
      seen[key] = true
      actor_hint = record['actor_hint'].to_s.strip
      matches = actor_hint.empty? ? [] : by_alias[normalize(actor_hint)].uniq { |entry| entry[1] }
      match = matches.one? ? matches.first : nil
      record['matched_actor'] = match&.first&.dig('name')
      record['attribution_status'] = match ? 'explicit_actor_match' : 'quarantined_no_defensible_actor_attribution'
      out << record
    end
    report = { 'source' => source_key, 'snapshot' => snapshot, 'mode' => write ? 'import' : 'plan',
               'records' => records.length, 'deduplicated' => seen.length,
               'matched_actors' => records.count { |r| r['matched_actor'] },
               'quarantined' => records.count { |r| r['attribution_status'].start_with?('quarantined') },
               'records_detail' => records.first(500) }
    write_matches(records, actors) if write
    if report_path
      FileUtils.mkdir_p(File.dirname(report_path))
      File.write(report_path, JSON.pretty_generate(report) + "\n")
    end
    puts "[#{source_key} #{write ? 'IMPORT' : 'PLAN'}] records=#{records.length} matched=#{report['matched_actors']} quarantined=#{report['quarantined']}"
  rescue JSON::ParserError, Psych::Exception => error
    raise "snapshot is malformed: #{error.message}"
  end

  private

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
