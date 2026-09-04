#!/usr/bin/env ruby
# frozen_string_literal: true

require 'optparse'
require_relative 'actor_store'
require_relative 'lib/import/observable_feed'

class UrlhausImporter
  include ObservableFeed
  SOURCE_KEY = 'urlhaus'
  SOURCE_URL = 'https://urlhaus-api.abuse.ch/v1/urls/recent/'
  ATTRIBUTION = 'URLhaus data is attributed to abuse.ch; URLs are secondary research leads and are not actor attribution without explicit source evidence.'

  def source_key = SOURCE_KEY
  def source_url = SOURCE_URL
  def attribution = ATTRIBUTION

  def run(argv)
    command = argv.shift
    options = { output: nil, snapshot: nil, report: nil, limit: nil }
    OptionParser.new do |opts|
      opts.on('--output DIR') { |v| options[:output] = v }
      opts.on('--snapshot PATH') { |v| options[:snapshot] = v }
      opts.on('--report-json PATH') { |v| options[:report] = v }
      opts.on('--limit N', Integer) { |v| options[:limit] = [v, 10_000].min }
    end.parse!(argv)
    case command
    when 'fetch'
      output = options[:output] || "data/imports/#{SOURCE_KEY}/#{Time.now.utc.strftime('%Y-%m-%d')}"
      fetch_json(SOURCE_URL, output: output, manifest: { 'source_name' => 'URLhaus', 'source_dataset_url' => SOURCE_URL,
                                                          'license_status' => 'abuse.ch terms and fair-use limits apply' },
                 headers: { 'Auth-Key' => ENV['THREATFOX_API_KEY'].to_s.strip })
    when 'plan', 'import'
      abort 'Missing --snapshot PATH' unless options[:snapshot]
      process_snapshot(options[:snapshot], report_path: options[:report], write: command == 'import', limit: options[:limit])
    else
      abort 'Usage: import-urlhaus.rb fetch|plan|import [--output DIR|--snapshot PATH]'
    end
  end

  private

  def normalize_record(row)
    return unless row.is_a?(Hash)
    url = row['url'].to_s.strip
    return unless url.match?(/\Ahttps?:\/\/[^\s]+\z/i) && url.bytesize <= 2048
    { 'observable_type' => 'url', 'observable' => url, 'source_record_id' => row['id'] || row['urlhaus_link'],
      'source_record_url' => row['urlhaus_link'] || "https://urlhaus.abuse.ch/url/#{row['id']}/",
      'threat' => row['threat'], 'tags' => Array(row['tags']).compact, 'status' => row['url_status'],
      'first_seen' => row['dateadded'], 'last_seen' => row['last_online'], 'confidence' => row['confidence'],
      'actor_hint' => row['actor'] || row['threat_actor'] }
  end
end

UrlhausImporter.new.run(ARGV) if __FILE__ == $PROGRAM_NAME
