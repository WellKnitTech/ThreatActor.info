#!/usr/bin/env ruby
# frozen_string_literal: true

# CISA KEV (Known Exploited Vulnerabilities) Importer
#
# Fetches CISA KEV catalog and maps CVEs to threat actors
# Source: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
# License: Public Domain (US Government)
#
# Usage:
#   ruby scripts/import-cisa-kev.rb fetch    # Download latest KEV data
#   ruby scripts/import-cisa-kev.rb map     # Map CVEs to actors in YAML

require 'json'
require 'net/http'
require 'uri'
require 'fileutils'
require 'yaml'
require_relative 'actor_store'

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_FILE = "data/cisa-kev/catalog.json"

COMMAND = ARGV[0] || "help"

# Known actor keywords in KEV 'vendorProject' and 'product' fields
ACTOR_KEYWORDS = {
  # Russian actors
  "APT28" => ["apt28", "fancy bear", "sofacy", "pawn storm", "sednit"],
  "APT29" => ["apt29", "cozy bear", "the duke", "nobelium"],
  "Sandworm" => ["sandworm", "voodoo bear", "electrum", "blackenergy", "industroyer", "notpetya"],
  "Turla" => ["turla", "snake", "waterbug", "venomous bear"],
  "Fancy Bear" => ["apt28", "fancy bear"],
  
  # Chinese actors
  "APT41" => ["apt41", "barium", "winnti", "wintrip", "blackfly"],
  "APT17" => ["apt17", "hidden lynx", "aurora panda"],
  "APT10" => ["apt10", "menupass", "stone panda"],
  
  # Iranian actors
  "APT33" => ["apt33", "elfin", "magnallium"],
  "MuddyWater" => ["muddywater", "seedworm", "static kitten"],
  "OilRig" => ["oilrig", "cobalt gypsy", "twisted kitten"],
  
  # North Korean actors
  "Lazarus" => ["lazarus", "hidden cobra", "zinc", "labyrinth chollima"],
  "Kimsuky" => ["kimsuky", "thallium", "velvet chollima"],
  
  # Other notable
  "LockBit" => ["lockbit"],
  "Conti" => ["conti", "wizard spider"],
  "REvil" => ["revil", "sodinokibi"],
  "BlackCat" => ["blackcat", "alphv"],
  "Clop" => ["clop", "cl0p"],
  "Akira" => ["akira"],
  "BlackSuit" => ["blacksuit"],
  "DragonEgg" => ["dragonegg"],
}.freeze

# CVE ID to actor mapping based on threat intelligence research
# These CVEs are known to be exploited by specific ransomware/APT groups
CVE_ACTOR_MAP = {
  # Conti / Wizard Spider
  "CVE-2018-13379" => "Conti",
  "CVE-2018-13374" => "Conti",
  "CVE-2020-0796" => "Conti",
  "CVE-2020-0609" => "Conti",
  "CVE-2020-0688" => "Conti",
  "CVE-2020-1472" => "Conti",
  "CVE-2021-1675" => "Conti",
  "CVE-2021-1732" => "Conti",
  "CVE-2021-21972" => "Conti",
  "CVE-2021-21985" => "Conti",
  "CVE-2021-22005" => "Conti",
  "CVE-2021-26855" => "Conti",
  "CVE-2021-26857" => "Conti",
  "CVE-2021-26858" => "Conti",
  "CVE-2021-27065" => "Conti",
  "CVE-2021-34527" => "Conti",
  "CVE-2019-1322" => "Conti",
  
  # LockBit
  "CVE-2019-0708" => "LockBit",
  "CVE-2019-11510" => "LockBit",
  "CVE-2019-19781" => "LockBit",
  "CVE-2019-7481" => "LockBit",
  "CVE-2021-22986" => "LockBit",
  "CVE-2021-31207" => "LockBit",
  "CVE-2021-34473" => "LockBit",
  "CVE-2021-34523" => "LockBit",
  "CVE-2021-36942" => "LockBit",
  "CVE-2021-44228" => "LockBit",
  "CVE-2021-20028" => "LockBit",
  "CVE-2022-21999" => "LockBit",
  "CVE-2022-22965" => "LockBit",
  "CVE-2022-36537" => "LockBit",
  "CVE-2023-0669" => "LockBit",
  "CVE-2023-27350" => "LockBit",
  "CVE-2023-27351" => "LockBit",
  "CVE-2023-4966" => "LockBit",
  "CVE-2023-27532" => "LockBit",
  "CVE-2024-1708" => "LockBit",
  "CVE-2024-1709" => "LockBit",
  
  # ALPHV / BlackCat
  "CVE-2016-0099" => "BlackCat",
  "CVE-2021-27876" => "BlackCat",
  "CVE-2021-27877" => "BlackCat",
  "CVE-2021-27878" => "BlackCat",
  "CVE-2022-24521" => "BlackCat",
  
  # Clop
  "CVE-2021-27101" => "Clop",
  "CVE-2021-27102" => "Clop",
  "CVE-2021-27103" => "Clop",
  "CVE-2021-27104" => "Clop",
  "CVE-2021-35211" => "Clop",
  "CVE-2023-0669" => "Clop",
  "CVE-2023-34362" => "Clop",
  "CVE-2023-27350" => "Clop",
  "CVE-2023-27351" => "Clop",
  "CVE-2024-50623" => "Clop",
  "CVE-2024-55956" => "Clop",
  "CVE-2025-61882" => "Clop",
  "CVE-2025-61884" => "Clop",
  
  # REvil / Sodinokibi
  "CVE-2018-8453" => "REvil",
  "CVE-2019-11539" => "REvil",
  "CVE-2019-2725" => "REvil",
  "CVE-2021-30116" => "REvil",
  "CVE-2021-30119" => "REvil",
  "CVE-2021-30110" => "REvil",
  
  # Akira
  "CVE-2019-6693" => "Akira",
  "CVE-2020-3259" => "Akira",
  "CVE-2020-3580" => "Akira",
  "CVE-2022-40684" => "Akira",
  "CVE-2023-20269" => "Akira",
  "CVE-2023-27532" => "Akira",
  "CVE-2023-28252" => "Akira",
  "CVE-2023-48788" => "Akira",
  "CVE-2024-37085" => "Akira",
  "CVE-2024-40711" => "Akira",
  "CVE-2024-40766" => "Akira",
  
  # BlackBasta
  "CVE-2021-42278" => "BlackBasta",
  "CVE-2021-42287" => "BlackBasta",
  "CVE-2021-40444" => "BlackBasta",
  "CVE-2022-26134" => "BlackBasta",
  "CVE-2022-27925" => "BlackBasta",
  "CVE-2022-30190" => "BlackBasta",
  "CVE-2022-30525" => "BlackBasta",
  "CVE-2022-41040" => "BlackBasta",
  "CVE-2022-41082" => "BlackBasta",
  "CVE-2022-1388" => "BlackBasta",
  "CVE-2023-22515" => "BlackBasta",
  "CVE-2023-3466" => "BlackBasta",
  "CVE-2023-3467" => "BlackBasta",
  "CVE-2023-3519" => "BlackBasta",
  "CVE-2023-42115" => "BlackBasta",
  "CVE-2024-21762" => "BlackBasta",
  "CVE-2024-23108" => "BlackBasta",
  "CVE-2024-23109" => "BlackBasta",
  "CVE-2024-23113" => "BlackBasta",
  "CVE-2024-3400" => "BlackBasta",
  "CVE-2024-26169" => "BlackBasta",
  "CVE-2024-1086" => "BlackBasta",
}.freeze

def fetch_kev
  puts "Fetching CISA KEV catalog..."
  
  uri = URI.parse(KEV_URL)
  response = Net::HTTP.get_response(uri)
  
  unless response.is_a?(Net::HTTPSuccess)
    puts "ERROR: #{response.code} - #{response.message}"
    return nil
  end
  
  JSON.parse(response.body)
rescue => e
  puts "ERROR: #{e.message}"
  nil
end

def save_kev(data)
  FileUtils.mkdir_p("data/cisa-kev")
  File.write(KEV_FILE, JSON.pretty_generate(data))
  puts "Saved: #{KEV_FILE}"
  count = (data['vulnerabilities'] || []).size
  puts "Total vulnerabilities: #{count}"
end

def load_kev
  return nil unless File.exist?(KEV_FILE)
  JSON.parse(File.read(KEV_FILE))
end

def find_actor_for_cve(cve_entry)
  vendor = cve_entry['vendorProject']&.downcase || ""
  product = cve_entry['product']&.downcase || ""
  description = cve_entry['shortDescription']&.downcase || ""
  cve_id = cve_entry['cveID']&.upcase || ""
  
  matched_actors = []
  
  # First, check CVE ID based mapping (higher priority - threat intel confirmed)
  if CVE_ACTOR_MAP[cve_id]
    matched_actors << CVE_ACTOR_MAP[cve_id]
  end
  
  # Also search in vendor, product, AND description for keywords
  search_text = "#{vendor} #{product} #{description}"
  
  ACTOR_KEYWORDS.each do |actor, keywords|
    keywords.each do |keyword|
      if search_text.include?(keyword)
        matched_actors << actor
        break
      end
    end
  end
  
  matched_actors.uniq
end

def map_cves_to_actors(kev_data)
  puts "Mapping CVEs to threat actors..."
  
  cve_actor_map = {}
  actor_cves = {}
  
  vulnerabilities = kev_data['vulnerabilities'] || []
  
  vulnerabilities.each do |cve|
    cve_id = cve['cveID']
    actors = find_actor_for_cve(cve)
    
    next if actors.empty?
    
    cve_actor_map[cve_id] = {
      'actors' => actors,
      'dateAdded' => cve['dateAdded'],
      'vendor' => cve['vendorProject'],
      'product' => cve['product'],
      'shortDescription' => cve['shortDescription']&.gsub(/\[.*?\]/, '')&.strip
    }
    
    actors.each do |actor|
      actor_cves[actor] ||= []
      actor_cves[actor] << {
        'cve' => cve_id,
        'dateAdded' => cve['dateAdded'],
        'vendor' => cve['vendorProject'],
        'product' => cve['product']
      }
    end
  end
  
  { cve_map: cve_actor_map, actor_map: actor_cves }
end

def update_actors_with_cves(actor_cves)
  puts "Updating actors with CVE data..."
  
  actors = ActorStore.load_all
  updated = 0
  
  actors.each do |actor|
    actor_name = actor['name']
    cves = actor_cves[actor_name]
    
    next unless cves && cves.any?
    
    actor['cisa_kev_cves'] = cves
    updated += 1
    
    puts "  #{actor_name}: #{cves.length} CVEs"
  end
  
  ActorStore.save_all(actors)
  puts "Updated #{updated} actors with CVE data"
end

case COMMAND
when "fetch"
  data = fetch_kev
  save_kev(data) if data

when "map"
  kev_data = load_kev
  unless kev_data
    puts "KEV data not found. Run: ruby scripts/import-cisa-kev.rb fetch"
    exit 1
  end
  
  result = map_cves_to_actors(kev_data)
  actor_cves = result[:actor_map]
  
  puts ""
  puts "CVEs mapped to actors:"
  actor_cves.each do |actor, cves|
    puts "  #{actor}: #{cves.length} CVEs"
  end
  
  puts ""
  puts "Updating YAML..."
  update_actors_with_cves(actor_cves)

when "full"
  # Fetch and map in one go
  data = fetch_kev
  exit(1) unless data
  
  save_kev(data)
  
  result = map_cves_to_actors(data)
  actor_cves = result[:actor_map]
  
  puts ""
  actor_cves.each do |actor, cves|
    puts "  #{actor}: #{cves.length} CVEs"
  end
  
  update_actors_with_cves(actor_cves)

else
  puts <<~HELP
    CISA KEV Importer
    
    Fetches CISA Known Exploited Vulnerabilities catalog and maps CVEs to threat actors.
    Source: #{KEV_URL}
    License: Public Domain (US Government)
    
    Usage:
      ruby scripts/import-cisa-kev.rb fetch   # Download latest KEV data
      ruby scripts/import-cisa-kev.rb map     # Map CVEs to actors in YAML
      ruby scripts/import-cisa-kev.rb full   # Fetch + map in one go
    
    Output:
      - data/cisa-kev/catalog.json (local cache)
      - Updated _data/actors/*.yml with cisa_kev_cves field
  HELP
end