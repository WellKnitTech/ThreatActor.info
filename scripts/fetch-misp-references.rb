#!/usr/bin/env ruby
# MISP Galaxy Reference Data Fetcher
# 
# Downloads cluster data to data/misp-reference/ for lookup
# Does NOT embed in YAML - keeps main file small

require 'fileutils'
require 'json'
require 'net/http'
require 'uri'

BASE_URL = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters"
REF_DIR = "data/misp-reference"
CLUSTERS = {
  "ransomware" => "#{BASE_URL}/ransomware.json",
  "sigma-rules" => "#{BASE_URL}/sigma-rules.json", 
  "botnet" => "#{BASE_URL}/botnet.json",
  "rat" => "#{BASE_URL}/rat.json",
  "malware" => "#{BASE_URL}/mitre-enterprise-attack-malware.json",
}

puts "Fetching MISP reference data..."
puts ""

FileUtils.mkdir_p(REF_DIR)

CLUSTERS.each do |name, url|
  print "  #{name}..."
  
  uri = URI.parse(url)
  response = Net::HTTP.get_response(uri)
  
  if response.is_a?(Net::HTTPSuccess)
    data = JSON.parse(response.body)
    count = data['values']&.size || 0
    
    File.write("#{REF_DIR}/#{name}.json", response.body)
    puts "#{count} entries"
  else
    puts "ERROR #{response.code}"
  end
end

puts ""
puts "Reference data saved to #{REF_DIR}/"
puts ""
puts "Usage: Load from #{REF_DIR}/ for enriched actor lookups"
puts "Example: data = JSON.parse(File.read('#{REF_DIR}/ransomware.json'))"