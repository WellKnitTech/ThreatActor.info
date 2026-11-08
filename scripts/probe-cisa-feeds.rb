#!/usr/bin/env ruby
# frozen_string_literal: true

# Live probe for CISA feed URLs / header variants. Not part of validate.sh.
# Run: ruby scripts/probe-cisa-feeds.rb
#
# Prints which configured CISA URLs return usable RSS/Atom, and whether a
# bare Ruby UA still 403s while browser-like headers succeed.

require 'fileutils'
require 'json'
require_relative 'lib/news_feed'

URLS = NewsFeed.feed_urls(
  NewsFeed::RSS_FEEDS.find { |f| f[:name] == 'CISA Advisories' }
).freeze

def probe(url, headers, label)
  started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  begin
    body = NewsFeed.http_get_with_timeouts(
      url,
      headers: headers,
      open_timeout: 8,
      read_timeout: 15
    )
    ms = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000).round
    usable = NewsFeed.feed_body_usable?(body)
    items = body.to_s.scan(/<(?:item|entry)[\s>]/i).size
    puts format('%-18s %4dms usable=%-5s items~%-4d %s', label, ms, usable, items, url)
    { 'label' => label, 'url' => url, 'ok' => usable, 'items' => items, 'ms' => ms, 'error' => nil }
  rescue StandardError => e
    ms = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000).round
    puts format('%-18s %4dms ERROR=%s %s', label, ms, e.message.to_s[0, 80], url)
    { 'label' => label, 'url' => url, 'ok' => false, 'items' => 0, 'ms' => ms, 'error' => e.message }
  end
end

def format_cell(row)
  if row['ok']
    "ok (items~#{row['items']}, #{row['ms']}ms)"
  else
    "FAIL #{row['error'].to_s[0, 80]}"
  end
end

ruby_ua = { 'User-Agent' => 'Ruby' }
ua_only = {
  'User-Agent' => NewsFeed::BROWSER_UA,
  'Accept' => 'application/rss+xml, application/atom+xml, application/xml, text/xml;q=0.9, */*;q=0.8',
  'Accept-Language' => 'en-US,en;q=0.9',
  'Accept-Encoding' => 'gzip, deflate'
}

puts '=== Bare Ruby UA (control) ==='
ruby_results = URLS.map { |url| probe(url, ruby_ua, 'ruby-ua') }

puts ''
puts '=== Browser-like headers (production) ==='
browser_results = URLS.map do |url|
  probe(url, NewsFeed.browser_http_headers(url: url), 'browser')
end

puts ''
puts '=== Browser UA + Accept only (no Sec-Fetch/Referer) ==='
ua_accept_results = URLS.map { |url| probe(url, ua_only, 'ua+accept') }

usable = browser_results.count { |r| r['ok'] }
puts ''
puts "Summary: #{usable}/#{browser_results.size} configured CISA URLs usable with production browser headers"

payload = {
  'usable_with_browser_headers' => usable,
  'total_urls' => browser_results.size,
  'ruby_ua' => ruby_results,
  'browser' => browser_results,
  'ua_accept' => ua_accept_results
}

summary_path = ENV['CISA_PROBE_SUMMARY_PATH']
summary_path = 'tmp/cisa-probe-summary.json' if summary_path.to_s.empty?
begin
  FileUtils.mkdir_p(File.dirname(summary_path))
  File.write(summary_path, JSON.pretty_generate(payload))
  puts "Wrote #{summary_path}"
rescue StandardError => e
  warn "Could not write probe summary: #{e.message}"
end

step_summary = ENV['GITHUB_STEP_SUMMARY']
if step_summary && !step_summary.empty?
  File.open(step_summary, 'a') do |io|
    io.puts '### CISA live probe'
    io.puts
    io.puts '| URL | ruby-ua | ua+accept | browser headers |'
    io.puts '| --- | --- | --- | --- |'
    URLS.each_with_index do |url, i|
      io.puts "| `#{url}` | #{format_cell(ruby_results[i])} | #{format_cell(ua_accept_results[i])} | #{format_cell(browser_results[i])} |"
    end
    io.puts
    io.puts "Usable with production browser headers: **#{usable}/#{browser_results.size}**"
  end
end

exit(usable.positive? ? 0 : 1)
