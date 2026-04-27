#!/usr/bin/env ruby

# frozen_string_literal: true

require 'fileutils'
require 'json'
require 'optparse'
require 'set'
require 'time'
require 'yaml'
require_relative 'actor_store'

class ActorCreator
  ACTORS_DIR = '_data/actors'
  THREAT_ACTORS_DIR = '_threat_actors'

  def initialize(argv)
    @argv = argv.dup
    @command = @argv.shift
    @options = {
      name: nil,
      description: nil,
      country: nil,
      aliases: [],
      url: nil,
      risk_level: nil,
      sector_focus: [],
      targeted_victims: [],
      first_seen: nil,
      last_activity: nil,
      external_id: nil,
      force: false
    }
  end

  def run
    case @command
    when 'new'
      parse_new_options
      create_actor
    else
      puts usage
      exit 1
    end
  end

  private

  def usage
    <<~TEXT
      Usage:
        ruby scripts/actor-creator.rb new [options]

      Options:
        --name NAME              Required: Primary actor name (e.g., "APT29")
        --description DESC     Required: Brief description
        --country CODE       Country code (e.g., "RU", "CN", "IR")
        --alias "NAME"       Alias (repeatable)
        --url PATH          URL path (e.g., "/apt29")
        --risk LEVEL        Risk level: Critical, High, Medium, Low
        --sector SECTOR   Sector targeted (repeatable)
        --victim COUNTRY   Targeted country (repeatable)
        --first-seen YEAR  First seen year
        --last-active YR  Last active year
        --external-id ID  MITRE ATT&CK ID (e.g., "G0016")
        --force           Overwrite existing actor

      Examples:
        ruby scripts/actor-creator.rb new --name "APT29" --country "CN" --description "Chinese state-sponsored actor"
        ruby scripts/actor-creator.rb new --name "APT29" --country "CN" --alias "Barium" --alias "APT-C3" --url "/apt29"
    TEXT
  end

  def parse_new_options
    parser = OptionParser.new do |opts|
      opts.banner = 'Usage: ruby scripts/actor-creator.rb new [options]'
      opts.on('--name NAME', 'Primary actor name (required)') { |v| @options[:name] = v }
      opts.on('--description DESC', 'Brief description (required)') { |v| @options[:description] = v }
      opts.on('--country CODE', 'Country code (e.g., RU, CN, IR)') { |v| @options[:country] = v }
      opts.on('--alias "NAME"', 'Alias (repeatable)') { |v| @options[:aliases] << v }
      opts.on('--url PATH', 'URL path (e.g., /apt29)') { |v| @options[:url] = v }
      opts.on('--risk LEVEL', 'Risk level: Critical, High, Medium, Low') { |v| @options[:risk_level] = v }
      opts.on('--sector SECTOR', 'Sector targeted (repeatable)') { |v| @options[:sector_focus] << v }
      opts.on('--victim COUNTRY', 'Targeted country (repeatable)') { |v| @options[:targeted_victims] << v }
      opts.on('--first-seen YEAR', 'First seen year') { |v| @options[:first_seen] = v }
      opts.on('--last-active YEAR', 'Last active year') { |v| @options[:last_activity] = v }
      opts.on('--external-id ID', 'MITRE ATT&CK ID') { |v| @options[:external_id] = v }
      opts.on('--force', 'Overwrite existing actor') { |v| @options[:force] = true }
    end

    parser.parse!(@argv)

    # Validate required options
    unless @options[:name] && @options[:description]
      puts "Error: --name and --description are required"
      puts usage
      exit 1
    end
  end

  def create_actor
    name = @options[:name]
    url = @options[:url] || "/#{slugify(name)}"

    # Check if actor exists
    actor_file = File.join(ACTORS_DIR, "#{slugify(url)}.yml")
    if File.exist?(actor_file) && !@options[:force]
      puts "Error: Actor already exists at #{actor_file}. Use --force to overwrite."
      exit 1
    end

    # Build actor data
    actor = {
      'name' => name,
      'description' => @options[:description],
      'url' => url,
      'aliases' => @options[:aliases].uniq,
      'country' => @options[:country],
      'risk_level' => @options[:risk_level],
      'sector_focus' => @options[:sector_focus].uniq,
      'targeted_victims' => @options[:targeted_victims].uniq,
      'first_seen' => @options[:first_seen],
      'last_activity' => @options[:last_activity],
      'external_id' => @options[:external_id],
      'source_name' => 'Manual Entry',
      'source_attribution' => 'Manually created by analyst'
    }

    # Clean up nil/empty values
    actor.reject! { |_, v| v.nil? || (v.respond_to?(:empty?) && v.empty?) }

    # Create actor YAML
    FileUtils.mkdir_p(ACTORS_DIR)
    File.write(actor_file, YAML.dump(actor))
    puts "Created actor: #{actor_file}"

    # Create markdown page
    page_dir = File.join(THREAT_ACTORS_DIR, url.sub(%r{^/}, '').sub(%r{/$}, '').split('/')[0..-2].join('/'))
    FileUtils.mkdir_p(page_dir) unless page_dir.empty?

    page_file = File.join(THREAT_ACTORS_DIR, "#{slugify(url)}.md")
    page = build_page(actor)
    File.write(page_file, page)
    puts "Created page: #{page_file}"

    puts "\nActor created successfully. Run validation and regenerate pages to complete."
  end

  def slugify(value)
    value.to_s.downcase.gsub(/[^a-z0-9]+/, '-').gsub(/^-|-$/, '')
  end

  def build_page(actor)
    <<~YAML
---
layout: threat_actor
title: "#{actor['name']}"
aliases: #{actor['aliases'].to_json}
description: "#{actor['description']}"
permalink: #{actor['url']}/
#{'country: ' + actor['country'] if actor['country']}
#{'risk_level: ' + actor['risk_level'] if actor['risk_level']}
#{'first_seen: ' + actor['first_seen'].to_s if actor['first_seen']}
#{'last_activity: ' + actor['last_activity'].to_s if actor['last_activity']}
---

## Introduction

#{actor['description']}

## Activities and Tactics

## Notable Campaigns

## Tactics, Techniques, and Procedures (TTPs)

## Notable Indicators of Compromise (IOCs)

## Malware and Tools

## Attribution and Evidence

## References
    YAML
  end
end

ActorCreator.new(ARGV).run if __FILE__ == $PROGRAM_NAME