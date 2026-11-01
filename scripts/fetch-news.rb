#!/usr/bin/env ruby
# frozen_string_literal: true

# RSS News Fetcher for Threat Actors
# Fetches recent security news, merges additively into the archive store,
# filters/deduplicates, and maps to threat actors.

require 'fileutils'
require 'net/http'
require 'uri'
require 'rss'
require 'json'
require 'rexml/document'
require 'time'
require 'timeout'

require_relative 'lib/news_feed'

def feed_http_headers
  NewsFeed.browser_http_headers
end

def open_feed(url)
  NewsFeed.fetch_url_with_deadline(
    url,
    deadline: NewsFeed::FEED_DEADLINE_SECONDS,
    headers: feed_http_headers,
    open_timeout: NewsFeed::OPEN_TIMEOUT,
    read_timeout: NewsFeed::READ_TIMEOUT
  )
end

def open_feed_within_budget(url, deadline_seconds)
  NewsFeed.fetch_url_with_deadline(
    url,
    deadline: deadline_seconds,
    headers: feed_http_headers,
    open_timeout: [NewsFeed::OPEN_TIMEOUT, deadline_seconds].min,
    read_timeout: [NewsFeed::READ_TIMEOUT, deadline_seconds].min
  )
end

def parse_feed_items(raw, feed)
  items = []
  rss = RSS::Parser.parse(raw, false)
  return [items, 'unrecognized feed format'] unless rss && rss.respond_to?(:items)

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

  [items, nil]
end

def parse_feed(feed, health, previous_entry: nil)
  items = []
  started = Time.now
  deadline_at = started + NewsFeed::FEED_DEADLINE_SECONDS
  last_error = nil
  used_url = nil

  begin
    NewsFeed.feed_urls(feed).each do |url|
      remaining = deadline_at - Time.now
      if remaining <= 0.05
        raise Timeout::Error, "deadline exceeded (#{NewsFeed::FEED_DEADLINE_SECONDS}s)"
      end

      begin
        raw = open_feed_within_budget(url, remaining)
        parsed, parse_error = parse_feed_items(raw, feed)
        if parse_error
          last_error = parse_error
          next
        end
        items = parsed
        used_url = url
        break
      rescue Timeout::Error
        raise
      rescue StandardError => e
        last_error = e.message.to_s[0..120]
        # Advance to alternate URL on HTTP/network failures (e.g. 403).
        next
      end
    end

    if used_url.nil?
      raise StandardError, last_error || 'all feed URLs failed'
    end

    entry = {
      'ok' => true,
      'items' => items.size,
      'latency_ms' => ((Time.now - started) * 1000).round,
      'url' => used_url
    }
    health[feed[:name]] = NewsFeed.merge_source_health_entry(entry, previous_entry)
  rescue Timeout::Error
    entry = {
      'ok' => false,
      'error' => "deadline exceeded (#{NewsFeed::FEED_DEADLINE_SECONDS}s)",
      'items' => 0,
      'latency_ms' => ((Time.now - started) * 1000).round,
      'timed_out' => true
    }
    health[feed[:name]] = NewsFeed.merge_source_health_entry(entry, previous_entry)
    warn "  Warning: #{feed[:name]} - deadline exceeded (#{health[feed[:name]]['latency_ms']}ms)"
  rescue StandardError => e
    entry = {
      'ok' => false,
      'error' => e.message.to_s[0..120],
      'items' => 0,
      'latency_ms' => ((Time.now - started) * 1000).round
    }
    health[feed[:name]] = NewsFeed.merge_source_health_entry(entry, previous_entry)
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

def fetch_beazley_articles(health, previous_health: {})
  articles = []
  feeds = [
    { url: 'https://labs.beazley.security/articles/atom.xml', source: 'Beazley Security Labs Articles' },
    { url: 'https://labs.beazley.security/advisories/atom.xml', source: 'Beazley Security Labs Advisories' }
  ]

  results = NewsFeed.map_concurrent(feeds, concurrency: [NewsFeed::FEED_CONCURRENCY, feeds.size].min) do |feed|
    started = Time.now
    previous_entry = previous_health[feed[:source]]
    begin
      raw = open_feed(feed[:url])
      parsed = parse_beazley_atom_entries(raw, feed[:source])
      entry = {
        'ok' => true,
        'items' => parsed.size,
        'latency_ms' => ((Time.now - started) * 1000).round
      }
      [feed[:source], parsed, NewsFeed.merge_source_health_entry(entry, previous_entry)]
    rescue Timeout::Error
      entry = {
        'ok' => false,
        'error' => "deadline exceeded (#{NewsFeed::FEED_DEADLINE_SECONDS}s)",
        'items' => 0,
        'latency_ms' => ((Time.now - started) * 1000).round,
        'timed_out' => true
      }
      warn "  Beazley (#{feed[:source]}): deadline exceeded"
      [feed[:source], [], NewsFeed.merge_source_health_entry(entry, previous_entry)]
    rescue StandardError => e
      entry = {
        'ok' => false,
        'error' => e.message.to_s[0..120],
        'items' => 0,
        'latency_ms' => ((Time.now - started) * 1000).round
      }
      warn "  Beazley (#{feed[:source]}): #{e.message.to_s[0..80]}"
      [feed[:source], [], NewsFeed.merge_source_health_entry(entry, previous_entry)]
    end
  end

  results.each do |source, parsed, entry|
    health[source] = entry
    articles.concat(parsed)
  end

  articles.uniq { |item| NewsFeed.canonicalize_url(item[:link]) }
end

# Always retry every configured feed. Permanent auto-drop was removed: a prior
# `dropped: true` flag is cleared and never skips the source.
def active_rss_feeds(_previous_health = {})
  NewsFeed::RSS_FEEDS
end

def emit_unhealthy_source_alerts(health)
  unhealthy = NewsFeed.unhealthy_sources(health)
  return if unhealthy.empty?

  puts ''
  puts "Unhealthy sources (>= #{NewsFeed::UNHEALTHY_FAILURE_THRESHOLD} consecutive failures):"
  unhealthy.each do |name, entry|
    failures = entry['consecutive_failures']
    error = entry['error']
    msg = "#{name}: #{failures} consecutive failures (#{error})"
    puts "  #{msg}"
    warn "::warning::News source unhealthy — #{msg}"
  end

  summary = ENV['GITHUB_STEP_SUMMARY']
  return if summary.to_s.empty?

  File.open(summary, 'a') do |io|
    io.puts '### Unhealthy news sources'
    io.puts
    io.puts "Sources with >= #{NewsFeed::UNHEALTHY_FAILURE_THRESHOLD} consecutive failures (still retried next run):"
    io.puts
    unhealthy.each do |name, entry|
      io.puts "- **#{name}**: #{entry['consecutive_failures']} failures — `#{entry['error']}`"
    end
    io.puts
  end
rescue StandardError => e
  warn "  Warning: could not write unhealthy-source summary (#{e.message})"
end

def fetch_news(health, previous_health: {})
  puts 'Fetching security news...'
  puts "  Concurrency: #{NewsFeed::FEED_CONCURRENCY}, per-feed deadline: #{NewsFeed::FEED_DEADLINE_SECONDS}s"

  feeds = active_rss_feeds(previous_health)
  results = NewsFeed.map_concurrent(feeds, concurrency: NewsFeed::FEED_CONCURRENCY) do |feed|
    local_health = {}
    items = parse_feed(feed, local_health, previous_entry: previous_health[feed[:name]])
    [feed[:name], items, local_health[feed[:name]]]
  end

  all_items = []
  results.each do |name, items, status|
    health[name] = status if status
    all_items.concat(items)
    suffix =
      if status && status['ok']
        "#{items.size} items (#{status['latency_ms']}ms)"
      elsif status && status['timed_out']
        "TIMED OUT (#{status['latency_ms']}ms, consecutive_failures=#{status['consecutive_failures']})"
      else
        "FAILED (#{status && status['error']}, consecutive_failures=#{status && status['consecutive_failures']})"
      end
    puts "  #{name}: #{suffix}"
  end

  beazley = fetch_beazley_articles(health, previous_health: previous_health)
  all_items.concat(beazley)
  puts "  Beazley Security Labs: #{beazley.size} items"

  emit_unhealthy_source_alerts(health)
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

  NewsFeed.normalize_source_health(data['source_health'] || {})
rescue StandardError
  {}
end

def main(argv)
  puts '=' * 50
  puts 'RSS News Fetcher (additive archive)'
  puts '=' * 50

  previous_health = previous_source_health
  health = previous_health.dup
  restore_only = argv.include?('--restore-only')
  skip_fetch = argv.include?('--skip-fetch') || restore_only

  raw_items =
    if (idx = argv.index('--from-json'))
      path = argv[idx + 1] or abort('Usage: fetch-news.rb --from-json PATH')
      puts "Loading fixtures from #{path}"
      load_items_from_json(path)
    elsif skip_fetch
      puts 'Skipping live feed fetch (preserving source_health, clearing dropped flags)'
      []
    else
      live_health = {}
      items = fetch_news(live_health, previous_health: previous_health)
      health = NewsFeed.normalize_source_health(previous_health).merge(live_health)
      items
    end

  # Ensure legacy dropped flags never linger in the committed store.
  health = NewsFeed.normalize_source_health(health)

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
