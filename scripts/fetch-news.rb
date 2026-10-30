#!/usr/bin/env ruby
# frozen_string_literal: true

# RSS News Fetcher for Threat Actors
# Fetches recent security news, filters/deduplicates, and maps to threat actors.

require 'net/http'
require 'uri'
require 'rss'
require 'open-uri'
require 'json'
require 'rexml/document'
require 'time'

require_relative 'lib/news_feed'

def parse_feed(feed, health)
  items = []
  started = Time.now

  begin
    raw = URI.parse(feed[:url]).open(
      read_timeout: 12,
      open_timeout: 8,
      'User-Agent' => 'ThreatActor.info daily-news/1.0'
    ).read
    rss = RSS::Parser.parse(raw, false)

    unless rss && rss.respond_to?(:items)
      health[feed[:name]] = { 'ok' => false, 'error' => 'unrecognized feed format', 'items' => 0 }
      return items
    end

    rss.items.first(NewsFeed::MAX_PER_FEED).each do |item|
      title = item.title.to_s.strip
      link = item.link.is_a?(String) ? item.link : item.link&.href
      link = link.to_s.strip
      next if title.empty? || link.empty?

      date = item.respond_to?(:date) ? item.date : nil
      date ||= item.respond_to?(:dc_date) ? item.dc_date : nil
      date ||= item.respond_to?(:pubDate) ? item.pubDate : nil
      date ||= item.respond_to?(:updated) ? item.updated : nil

      items << {
        title: title[0..200],
        link: link,
        date: date,
        source: feed[:name],
        weight: feed[:weight] || 1,
        category: feed[:category] || :security
      }
    end

    health[feed[:name]] = {
      'ok' => true,
      'items' => items.size,
      'latency_ms' => ((Time.now - started) * 1000).round
    }
  rescue StandardError => e
    health[feed[:name]] = { 'ok' => false, 'error' => e.message.to_s[0..120], 'items' => 0 }
    warn "  Warning: #{feed[:name]} - #{e.message.to_s[0..80]}"
  end

  items
end

def parse_beazley_atom_entries(xml, source)
  doc = REXML::Document.new(xml)
  entries = []

  REXML::XPath.each(doc, '//entry') do |entry|
    title = entry.elements['title']&.text&.strip
    link = entry.elements['link']&.attributes&.[]('href')&.strip
    published = entry.elements['published']&.text&.strip || entry.elements['updated']&.text&.strip
    next if title.to_s.empty? || link.to_s.empty?

    entries << {
      title: title[0..200],
      link: link,
      source: source,
      date: published,
      weight: 2,
      category: :security
    }
  end

  entries.first(NewsFeed::MAX_PER_FEED)
end

def fetch_beazley_articles(health)
  articles = []
  feeds = [
    { url: 'https://labs.beazley.security/articles/atom.xml', source: 'Beazley Security Labs Articles' },
    { url: 'https://labs.beazley.security/advisories/atom.xml', source: 'Beazley Security Labs Advisories' }
  ]

  feeds.each do |feed|
    started = Time.now
    begin
      raw = URI.parse(feed[:url]).open(
        read_timeout: 12,
        open_timeout: 8,
        'User-Agent' => 'ThreatActor.info daily-news/1.0'
      ).read
      parsed = parse_beazley_atom_entries(raw, feed[:source])
      articles.concat(parsed)
      health[feed[:source]] = {
        'ok' => true,
        'items' => parsed.size,
        'latency_ms' => ((Time.now - started) * 1000).round
      }
    rescue StandardError => e
      health[feed[:source]] = { 'ok' => false, 'error' => e.message.to_s[0..120], 'items' => 0 }
      warn "  Beazley (#{feed[:source]}): #{e.message.to_s[0..80]}"
    end
  end

  articles.uniq { |item| NewsFeed.canonicalize_url(item[:link]) }
end

def fetch_news(health)
  puts 'Fetching security news...'

  all_items = []
  NewsFeed::RSS_FEEDS.each do |feed|
    items = parse_feed(feed, health)
    all_items.concat(items)
    status = health[feed[:name]]
    suffix = status && status['ok'] ? "#{items.size} items" : "FAILED (#{status && status['error']})"
    puts "  #{feed[:name]}: #{suffix}"
  end

  beazley = fetch_beazley_articles(health)
  all_items.concat(beazley)
  puts "  Beazley Security Labs: #{beazley.size} items"

  all_items
end

def load_items_from_json(path)
  data = JSON.parse(File.read(path))
  rows = data.is_a?(Array) ? data : Array(data['items'])
  rows.map do |row|
    {
      title: row['title'],
      link: row['link'],
      date: row['date'],
      source: row['source'] || 'fixture',
      weight: row['weight'] || 1,
      category: (row['category'] || 'security').to_sym
    }
  end
end

def save_news(output)
  puts "Saving to #{NewsFeed::OUTPUT_FILE}..."
  File.write(NewsFeed::OUTPUT_FILE, JSON.pretty_generate(output))
  matched = output['actor_news'].count { |_, v| v.any? }
  puts "Items kept: #{output['items'].size}"
  puts "Actors with news: #{matched}"
  dead = output['source_health'].count { |_, v| !v['ok'] }
  puts "Unhealthy sources: #{dead}" if dead.positive?
end

def main(argv)
  puts '=' * 50
  puts 'RSS News Fetcher'
  puts '=' * 50

  health = {}
  raw_items =
    if (idx = argv.index('--from-json'))
      path = argv[idx + 1] or abort('Usage: fetch-news.rb --from-json PATH')
      puts "Loading fixtures from #{path}"
      load_items_from_json(path)
    else
      fetch_news(health)
    end

  keyword_index = NewsFeed.build_keyword_index
  processed = NewsFeed.process_items(raw_items, keyword_index: keyword_index)

  sources = NewsFeed::RSS_FEEDS.map { |f| f[:name] }
  sources |= health.keys
  output = NewsFeed.build_output(processed, source_health: health, sources: sources)
  save_news(output)

  puts ''
  puts 'Top actors with news:'
  output['actor_news']
    .select { |_, v| v.any? }
    .sort_by { |_, v| -v.size }
    .first(10)
    .each { |k, v| puts "  #{k}: #{v.size} articles" }

  puts ''
  puts 'Sample recent items:'
  output['items'].first(5).each do |item|
    actors = Array(item['actors']).map { |a| a['name'] }.join(', ')
    puts "  - #{item['title'][0..90]}"
    puts "    #{item['source']} | actors: #{actors.empty? ? '(none)' : actors}"
  end
end

main(ARGV) if $PROGRAM_NAME == __FILE__
