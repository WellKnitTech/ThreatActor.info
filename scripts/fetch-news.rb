#!/usr/bin/env ruby
# frozen_string_literal: true

# RSS News Fetcher for Threat Actors
# Fetches recent security news and maps to threat actors

require 'net/http'
require 'uri'
require 'rss'
require 'open-uri'
require 'yaml'
require 'json'

DATA_FILE = '_data/threat_actors.yml'
OUTPUT_FILE = '_data/news_feed.yml'

# Security RSS feeds
RSS_FEEDS = [
  { name: 'BleepingComputer', url: 'https://www.bleepingcomputer.com/feed/', weight: 2 },
  { name: 'The Hacker News', url: 'https://feeds.feedburner.com/TheHackersNews', weight: 2 },
  { name: 'KrebsOnSecurity', url: 'https://krebsonsecurity.com/feed/', weight: 2 },
  { name: 'DarkReading', url: 'https://www.darkreading.com/rss.xml', weight: 1 },
  { name: 'SecurityWeek', url: 'https://www.securityweek.com/feed', weight: 1 },
  { name: 'Threatpost', url: 'https://threatpost.com/feed/', weight: 1 },
].freeze

# Actor name keywords for matching
ACTOR_KEYWORDS = {
  # Major APT groups - Russian
  'APT28' => ['apt28', 'fancy bear', 'sofacy', 'pawn storm', 'sednit', 'strontium', 'forest Blizzard'],
  'APT29' => ['apt29', 'cozy bear', 'the duke', 'nobelium', 'yttrium', 'midnight blizzard'],
  'Sandworm' => ['sandworm', 'voodoo bear', 'electrum', 'industroyer', 'notpetya', 'bare rock'],
  'Turla' => ['turla', 'snake', 'waterbug', 'venomous bear', 'urobos'],
  
  # Major APT groups - Chinese
  'APT41' => ['apt41', 'winnti', 'barium', 'wintrip', 'blackfly', 'wicked panda'],
  'APT10' => ['apt10', 'menupass', 'stone panda', 'menupass'],
  'APT17' => ['apt17', 'hidden lynx', 'aurora panda'],
  'Barium' => ['barium', 'winnti group'],
  
  # Major APT groups - Iranian
  'APT33' => ['apt33', 'elfin', 'magnallium'],
  'MuddyWater' => ['muddywater', 'seedworm', 'static kitten', 'muddy water'],
  'OilRig' => ['oilrig', 'cobalt gypsy', 'twisted kitten', 'elix'],
  
  # Major APT groups - North Korean
  'Lazarus' => ['lazarus', 'hidden cobra', 'zinc', 'labyrinth chollima', 'zinc'],
  'Kimsuky' => ['kimsuky', 'thallium', 'velvet chollima', 'zinc'],
  
  # Major ransomware
  'LockBit' => ['lockbit', 'lockbit 3.0', 'lockbit ransomware'],
  'Conti' => ['conti', 'wizard spider', 'wizard spider'],
  'REvil' => ['revil', 'sodinokibi', 'sodiniki'],
  'BlackCat' => ['alphv', 'blackcat', 'blackcat ransomware'],
  'Clop' => ['clop', 'cl0p', 'clop ransomware'],
  'Akira' => ['akira ransomware'],
  'BlackBasta' => ['blackbasta', 'basta ransomware'],
  'Royal' => ['royal ransomware', 'royal dp'],
  'Knight' => ['knight ransomware'],
  'Play' => ['play ransomware'],
  'Rhysida' => ['rhysida ransomware'],
  'Cuba' => ['cuba ransomware', 'cuba'],
  
  # Initial access brokers
  'Fin7' => ['fin7', 'carbanak', 'navigator', 'fin 7'],
  'Carbanak' => ['carbanak', 'carbon spider'],
  'TA505' => ['ta505', 'fin一致的', 'lovense'],
  
  # Other notable
  'Emotet' => ['emotet', 'heodo'],
  'TrickBot' => ['trickbot', 'trickster'],
  'Qakbot' => ['qakbot', 'qbot', 'quakbot'],
  'IcedID' => ['icedid', 'bokbot'],
  'Cobalt' => ['cobalt', 'cobalt strike'],
  'Metasploit' => ['metasploit'],
  'Mimikatz' => ['mimikatz'],
  
  # State-sponsored groups
  'Mustang Panda' => ['mustang panda', 'bvp22', 'temp not'],
  'Ghost Shark' => ['ghost shark', 'gothic panda'],
  'Patchwork' => ['patchwork', 'dropping eagle'],
  'Sidewinder' => ['sidewinder', 'groundbait'],
}.freeze

def parse_feed(feed)
  items = []
  
  begin
    raw = URI.parse(feed[:url]).open(read_timeout: 10).read
    rss = RSS::Parser.parse(raw)
    
    rss.items.first(15).each do |item|
      next unless item.title && item.link
      
      items << {
        title: item.title[0..200],
        link: item.link,
        date: item.date&.iso8601,
        source: feed[:name],
        weight: feed[:weight] || 1
      }
    end
  rescue => e
    puts "  Warning: #{feed[:name]} - #{e.message[0..40]}"
  end
  
  items
end

def match_actors(title, text)
  title_lower = title.downcase
  text_lower = text.downcase
  
  matched = []
  
  ACTOR_KEYWORDS.each do |actor, keywords|
    keywords.each do |kw|
      if title_lower.include?(kw) || text_lower.include?(kw)
        matched << actor
        break
      end
    end
  end
  
  matched.uniq
end

def fetch_news
  puts "Fetching security news..."
  
  all_items = []
  
  RSS_FEEDS.each do |feed|
    items = parse_feed(feed)
    all_items.concat(items)
    puts "  #{feed[:name]}: #{items.size} items"
  end
  
  # Sort by date, newest first
  all_items.sort_by! { |i| i[:date] || '1970-01-01' }
  all_items.reverse!
  
  all_items.first(100)  # Keep recent 100
end

def map_actors_to_news(news_items)
  puts "Mapping to threat actors..."
  
  actor_news = {}
  
  news_items.each do |item|
    matches = match_actors(item[:title], item[:title])
    
    matches.each do |actor|
      actor_news[actor] ||= []
      actor_news[actor] << {
        title: item[:title],
        link: item[:link],
        date: item[:date],
        source: item[:source]
      }
    end
  end
  
  actor_news.each do |actor, news|
    # Keep only 5 most recent per actor
    actor_news[actor] = news.first(5)
  end
  
  actor_news
end

def save_news(actor_news)
  puts "Saving to #{OUTPUT_FILE}..."
  
  # Ensure all keys are strings for YAML compatibility
  string_actor_news = {}
  actor_news.each do |k, v|
    string_actor_news[k.to_s] = v
  end
  
  # Build structured output with string keys
  output = {
    'updated' => Time.now.utc.iso8601,
    'sources' => RSS_FEEDS.map { |f| f[:name] },
    'actor_news' => string_actor_news
  }
  
  # Use JSON for safer serialization
  File.write(OUTPUT_FILE, JSON.pretty_generate(output))
  
  matched_count = string_actor_news.keys.select { |k| string_actor_news[k].any? }.size
  puts "Actors with news: #{matched_count}"
end

# Main
if __FILE__ == $0
  puts "=" * 50
  puts "RSS News Fetcher"
  puts "=" * 50
  
  news_items = fetch_news
  actor_news = map_actors_to_news(news_items)
  save_news(actor_news)
  
  puts ""
  puts "Top actors with news:"
  actor_news.select { |k, v| v.any? }
        .sort_by { |k, v| -v.size }
        .first(10)
        .each { |k, v| puts "  #{k}: #{v.size} articles" }
end