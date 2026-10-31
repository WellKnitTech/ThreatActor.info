#!/usr/bin/env ruby
# frozen_string_literal: true

# RSS News Fetcher for Threat Actors
# Fetches recent security news, merges additively into the archive store,
# filters/deduplicates, and maps to threat actors.

require 'fileutils'
require 'net/http'
require 'uri'
require 'rss'
require 'open-uri'
require 'json'
require 'rexml/document'
require 'time'
require 'timeout'

require_relative 'lib/news_feed'

def feed_http_headers
  {
    'User-Agent' => NewsFeed::BROWSER_UA,
    'Accept' => 'application/rss+xml, application/atom+xml, application/xml, text/xml;q=0.9, */*;q=0.8'
  }
end

def open_feed(url)
  URI.parse(url).open(
    read_timeout: NewsFeed::READ_TIMEOUT,
    open_timeout: NewsFeed::OPEN_TIMEOUT,
    **feed_http_headers
  ).read
end

def parse_feed(feed, health)
  items = []
  started = Time.now

  begin
    raw = Timeout.timeout(NewsFeed::FEED_DEADLINE_SECONDS) { open_feed(feed[:url]) }
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
  rescue Timeout::Error
    health[feed[:name]] = {
      'ok' => false,
      'error' => "deadline exceeded (#{NewsFeed::FEED_DEADLINE_SECONDS}s)",
      'items' => 0,
      'latency_ms' => ((Time.now - started) * 1000).round
    }
    warn "  Warning: #{feed[:name]} - deadline exceeded"
  rescue StandardError => e
    health[feed[:name]] = {
      'ok' => false,
      'error' => e.message.to_s[0..120],
      'items' => 0,
      'latency_ms' => ((Time.now - started) * 1000).round
    }
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
      raw = Timeout.timeout(NewsFeed::FEED_DEADLINE_SECONDS) { open_feed(feed[:url]) }
      parsed = parse_beazley_atom_entries(raw, feed[:source])
      articles.concat(parsed)
      health[feed[:source]] = {
        'ok' => true,
        'items' => parsed.size,
        'latency_ms' => ((Time.now - started) * 1000).round
      }
    rescue Timeout::Error
      health[feed[:source]] = {
        'ok' => false,
        'error' => "deadline exceeded (#{NewsFeed::FEED_DEADLINE_SECONDS}s)",
        'items' => 0,
        'latency_ms' => ((Time.now - started) * 1000).round
      }
      warn "  Beazley (#{feed[:source]}): deadline exceeded"
    rescue StandardError => e
      health[feed[:source]] = {
        'ok' => false,
        'error' => e.message.to_s[0..120],
        'items' => 0,
        'latency_ms' => ((Time.now - started) * 1000).round
      }
      warn "  Beazley (#{feed[:source]}): #{e.message.to_s[0..80]}"
    end
  end

  articles.uniq { |item| NewsFeed.canonicalize_url(item[:link]) }
end

def active_rss_feeds(previous_health = {})
  NewsFeed::RSS_FEEDS.reject do |feed|
    # Only skip feeds we already marked dropped after a browser-UA 403.
    # A bare historical 403 (old bot UA) still gets one retry with BROWSER_UA.
    prev = previous_health[feed[:name]]
    if prev.is_a?(Hash) && prev['dropped']
      warn "  Skipping #{feed[:name]} (dropped after 403 Forbidden with browser UA)"
      true
    else
      false
    end
  end
end

def fetch_news(health, previous_health: {})
  puts 'Fetching security news...'

  all_items = []
  feeds = active_rss_feeds(previous_health)
  feeds.each do |feed|
    items = parse_feed(feed, health)
    all_items.concat(items)
    status = health[feed[:name]]
    suffix = status && status['ok'] ? "#{items.size} items (#{status['latency_ms']}ms)" : "FAILED (#{status && status['error']})"
    puts "  #{feed[:name]}: #{suffix}"

    # If this run hits 403 with the browser UA, record drop recommendation.
    if NewsFeed.drop_feed_on_forbidden?(status)
      health[feed[:name]]['dropped'] = true
      warn "  Dropping #{feed[:name]} from future runs (403 Forbidden with browser UA)"
    end
  end

  # Mark intentionally skipped feeds in health for visibility.
  (NewsFeed::RSS_FEEDS.map { |f| f[:name] } - feeds.map { |f| f[:name] }).each do |name|
    health[name] ||= {
      'ok' => false,
      'error' => 'dropped after persistent 403 Forbidden',
      'items' => 0,
      'dropped' => true
    }
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
      canonical_url: row['canonical_url'],
      date: row['date'],
      source: row['source'] || 'fixture',
      weight: row['weight'] || 1,
      category: (row['category'] || 'security').to_sym,
      cves: row['cves'] || [],
      tags: row['tags'] || [],
      actors: row['actors'] || []
    }
  end
end

def save_news(output)
  puts "Saving to #{NewsFeed::OUTPUT_FILE}..."
  FileUtils.mkdir_p(File.dirname(NewsFeed::OUTPUT_FILE))
  File.write(NewsFeed::OUTPUT_FILE, JSON.pretty_generate(output))
  matched = output['actor_news'].count { |_, v| Array(v).any? }
  puts "Items in archive: #{output['item_count_total']}"
  puts "Items on /news/ display: #{output['item_count']}"
  puts "Actors with news: #{matched}"
  dead = output['source_health'].count { |_, v| !v['ok'] }
  puts "Unhealthy sources: #{dead}" if dead.positive?
end

def previous_source_health
  data = NewsFeed.load_json_file(NewsFeed::OUTPUT_FILE)
  return {} unless data.is_a?(Hash)

  data['source_health'] || {}
rescue StandardError
  {}
end

def main(argv)
  puts '=' * 50
  puts 'RSS News Fetcher (additive archive)'
  puts '=' * 50

  health = {}
  restore_only = argv.include?('--restore-only')
  skip_fetch = argv.include?('--skip-fetch') || restore_only

  raw_items =
    if (idx = argv.index('--from-json'))
      path = argv[idx + 1] or abort('Usage: fetch-news.rb --from-json PATH')
      puts "Loading fixtures from #{path}"
      load_items_from_json(path)
    elsif skip_fetch
      puts 'Skipping live feed fetch'
      []
    else
      fetch_news(health, previous_health: previous_source_health)
    end

  keyword_index = NewsFeed.build_match_index
  existing = NewsFeed.load_existing_store
  puts "Existing stored items: #{existing.size}"

  fresh =
    if raw_items.empty?
      []
    elsif argv.include?('--from-json') && argv.include?('--no-window')
      # Historical restore path: trust callers to supply candidates, still
      # enrich + security-filter without the rolling fetch window.
      raw_items.select do |item|
        category = item[:category] || :security
        NewsFeed.safe_http_url?(item[:link]) &&
          NewsFeed.security_relevant?(item[:title], category: category)
      end.filter_map { |item| NewsFeed.enrich_item(item, keyword_index) }
    else
      NewsFeed.process_fresh_items(raw_items, keyword_index: keyword_index)
    end
  puts "Fresh candidates: #{fresh.size}"

  merged = NewsFeed.merge_additive(existing, fresh, keyword_index: keyword_index)
  puts "Merged archive size: #{merged.size}"

  archive_months = NewsFeed.write_monthly_archives!(merged)
  sources = NewsFeed::RSS_FEEDS.map { |f| f[:name] }
  sources |= health.keys
  output = NewsFeed.build_output(
    merged,
    source_health: health,
    sources: sources,
    archive_months: archive_months
  )
  save_news(output)

  puts ''
  puts 'Top actors with news:'
  output['actor_news']
    .select { |_, v| Array(v).any? }
    .sort_by { |_, v| -Array(v).size }
    .first(10)
    .each { |k, v| puts "  #{k}: #{Array(v).size} articles" }

  puts ''
  puts 'Sample recent items:'
  output['items'].first(5).each do |item|
    actors = Array(item['actors']).map { |a| a['name'] }.join(', ')
    puts "  - #{item['title'][0..90]}"
    puts "    #{item['source']} | actors: #{actors.empty? ? '(none)' : actors}"
  end
end

main(ARGV) if $PROGRAM_NAME == __FILE__
