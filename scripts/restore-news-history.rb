#!/usr/bin/env ruby
# frozen_string_literal: true

# One-shot (idempotent) restore of news items from git history of
# `_data/news_feed.yml`, re-filtered and re-matched with the current rules,
# then merged into the additive archive store.
#
# Usage:
#   ruby scripts/restore-news-history.rb
#   ruby scripts/restore-news-history.rb --max-commits 80

require 'json'
require 'open3'
require 'time'

require_relative 'lib/news_feed'

def git_show_news(rev)
  out, status = Open3.capture2('git', 'show', "#{rev}:_data/news_feed.yml")
  return nil unless status.success?

  JSON.parse(out)
rescue JSON::ParserError
  nil
end

def collect_history_items(max_commits:)
  log, status = Open3.capture2('git', 'log', '--format=%H', '--', '_data/news_feed.yml')
  abort('git log failed') unless status.success?

  revs = log.split("\n").reject(&:empty?).first(max_commits)
  by_url = {}

  revs.each do |rev|
    data = git_show_news(rev)
    next unless data.is_a?(Hash)

    Array(data['items']).each do |item|
      url = NewsFeed.canonicalize_url(item['canonical_url'] || item['link'])
      next unless url

      entry = {
        'title' => item['title'],
        'link' => url,
        'canonical_url' => url,
        'date' => item['date'],
        'source' => item['source'],
        'weight' => item['weight'] || 1,
        'category' => 'security',
        'cves' => item['cves'] || [],
        'tags' => item['tags'] || [],
        'actors' => item['actors'] || []
      }
      prev = by_url[url]
      if prev.nil? || (entry['date'].to_s > prev['date'].to_s)
        by_url[url] = entry
      end
    end

    Array(data['actor_news']).each do |actor_name, items|
      Array(items).each do |item|
        # Support both legacy array rows and any nested hashes.
        row = item.is_a?(Hash) ? item : {}
        url = NewsFeed.canonicalize_url(row['link'])
        next unless url

        entry = {
          'title' => row['title'],
          'link' => url,
          'canonical_url' => url,
          'date' => row['date'],
          'source' => row['source'] || 'historical',
          'weight' => 1,
          'category' => 'security',
          'cves' => row['cves'] || [],
          'tags' => row['tags'] || [],
          'actors' => [{ 'name' => actor_name, 'url' => '', 'matched_alias' => '' }]
        }
        prev = by_url[url]
        if prev
          names = Array(prev['actors']).map { |a| a['name'] }
          unless names.include?(actor_name)
            prev['actors'] = Array(prev['actors']) + entry['actors']
          end
          if (entry['date'].to_s > prev['date'].to_s) && entry['title']
            prev['title'] = entry['title']
            prev['date'] = entry['date']
            prev['source'] = entry['source'] if entry['source']
          end
        else
          by_url[url] = entry
        end
      end
    end
  end

  by_url.values
end

def main(argv)
  max_commits = 120
  if (idx = argv.index('--max-commits'))
    max_commits = Integer(argv[idx + 1])
  end

  puts "Collecting news history from up to #{max_commits} commits..."
  raw = collect_history_items(max_commits: max_commits)
  puts "Unique URLs from git history: #{raw.size}"

  keyword_index = NewsFeed.build_keyword_index
  existing = NewsFeed.load_existing_store
  puts "Existing store size: #{existing.size}"

  candidates = raw.select do |item|
    NewsFeed.safe_http_url?(item['link']) &&
      NewsFeed.security_relevant?(item['title'], category: :security)
  end
  puts "Security-relevant historical candidates: #{candidates.size}"

  enriched = candidates.filter_map { |item| NewsFeed.enrich_item(item, keyword_index) }
  merged = NewsFeed.merge_additive(existing, enriched, keyword_index: keyword_index)
  puts "Merged archive size: #{merged.size}"

  archive_months = NewsFeed.write_monthly_archives!(merged)
  prior = NewsFeed.load_json_file(NewsFeed::OUTPUT_FILE) || {}
  health = prior['source_health'] || {}
  sources = prior['sources'] || NewsFeed::RSS_FEEDS.map { |f| f[:name] }

  output = NewsFeed.build_output(
    merged,
    source_health: health,
    sources: sources,
    archive_months: archive_months
  )
  File.write(NewsFeed::OUTPUT_FILE, JSON.pretty_generate(output))
  puts "Wrote #{NewsFeed::OUTPUT_FILE} (display #{output['item_count']} / total #{output['item_count_total']})"
  puts "Archive months: #{archive_months.map { |m| m['month'] }.join(', ')}"
end

main(ARGV) if $PROGRAM_NAME == __FILE__
