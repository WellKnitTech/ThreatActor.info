# frozen_string_literal: true

# Resolves paths to MITRE ATT&CK STIX bundles (enterprise, mobile, ics) and ATT&CK release version.
# Priority: newest dated snapshot under data/imports/mitre-attack/ -> data/mitre-cache/active.yml -> optional network fetch.

require 'fileutils'
require 'json'
require 'net/http'
require 'uri'
require 'yaml'

require_relative 'mitre_common'

class MitreVersionResolver
  CACHE_DIR = 'data/mitre-cache'
  ACTIVE_FILE = File.join(CACHE_DIR, 'active.yml').freeze
  SNAPSHOT_GLOB = 'data/imports/mitre-attack/*/manifest.yml'
  DOMAINS = %w[enterprise mobile ics].freeze

  class << self
    # @return [Array] [ bundle_paths Hash{domain=>path}, meta Hash ]
    def resolve(fetch_network: false)
      meta = { 'retrieved_at' => nil, 'domains' => {}, 'active_version' => nil }

      paths, meta = resolve_from_snapshot(meta)
      return [paths, finalize_meta(meta)] if paths && paths.size >= 3

      paths, meta = resolve_from_active_yml(meta)
      return [paths, finalize_meta(meta)] if paths && paths.size >= 3

      if fetch_network
        paths, meta = fetch_all_domains_network(meta)
        return [paths, finalize_meta(meta)] if paths && paths.any?
      end

      paths, meta = resolve_legacy_enterprise_only(meta)
      return [paths, finalize_meta(meta)] if paths && paths.any?

      [nil, finalize_meta(meta)]
    end

    def unified_version(domains_hash)
      vers = (domains_hash || {}).values.filter_map do |d|
        next unless d.is_a?(Hash)

        (d['version'] || d[:version]).to_s.strip
      end.reject(&:empty?).uniq
      return vers.first if vers.size <= 1

      vers.max_by { |v| safe_gem_version(v) }
    end

    private

    def safe_gem_version(v)
      Gem::Version.new(v)
    rescue ArgumentError
      Gem::Version.new('0')
    end

    def finalize_meta(meta)
      meta['active_version'] ||= unified_version(meta['domains'])
      meta
    end

    def resolve_from_snapshot(meta)
      snap_manifest = Dir.glob(SNAPSHOT_GLOB).max_by { |p| File.mtime(p) }
      return [nil, meta] unless snap_manifest && File.exist?(snap_manifest)

      root = File.dirname(snap_manifest)
      yml = YAML.safe_load(File.read(snap_manifest), permitted_classes: [Time, Date], aliases: true) || {}
      bundle_paths = {}
      domains_meta = {}

      (yml['bundles'] || {}).each do |domain, info|
        fn = info['filename']
        p = File.join(root, fn)
        next unless File.exist?(p)

        ver = info['attack_version']
        if ver.to_s.empty?
          begin
            ver = MitreCommon.attack_version_from_bundle(JSON.parse(File.read(p)))
          rescue StandardError
            ver = nil
          end
        end

        bundle_paths[domain] = p
        domains_meta[domain] = {
          'version' => ver,
          'source_url' => info['url'],
          'retrieved_at' => yml['retrieved_at'],
          'path' => p
        }
      end

      return [nil, meta] unless bundle_paths.size >= 3

      meta['retrieved_at'] = yml['retrieved_at']
      meta['domains'] = domains_meta
      [bundle_paths, meta]
    end

    def resolve_from_active_yml(meta)
      return [nil, meta] unless File.exist?(ACTIVE_FILE)

      yml = YAML.safe_load(File.read(ACTIVE_FILE), permitted_classes: [Time, Date], aliases: true) || {}
      bundle_paths = {}
      domains_meta = {}

      src = yml['domains'] || {}
      src.each do |domain, info|
        path = info['path']
        path = File.join(CACHE_DIR, info['filename']) if path.to_s.empty? && info['filename']
        next unless path && File.exist?(path)

        bundle_paths[domain] = path
        domains_meta[domain] = info.merge('path' => path)
      end

      return [nil, meta] unless bundle_paths.size >= 3

      meta['retrieved_at'] = yml['retrieved_at']
      meta['domains'] = domains_meta
      meta['active_version'] = yml['active_version']
      [bundle_paths, meta]
    end

    def fetch_all_domains_network(meta)
      FileUtils.mkdir_p(CACHE_DIR)
      bundle_paths = {}
      domains_meta = {}
      retrieved = Time.now.utc.iso8601

      DOMAINS.each do |domain|
        url = MitreCommon.bundle_url(domain)
        tmp = File.join(CACHE_DIR, ".download-#{domain}-#{Process.pid}.json")
        download_url(url, tmp)
        data = JSON.parse(File.read(tmp))
        ver = MitreCommon.attack_version_from_bundle(data)
        final_name = if ver.to_s.empty?
                       MitreCommon::DOMAIN_FILES[domain][:file]
                     else
                       MitreCommon.versioned_bundle_filename(domain, ver)
                     end
        final_path = File.join(CACHE_DIR, final_name)
        FileUtils.mv(tmp, final_path)

        bundle_paths[domain] = final_path
        domains_meta[domain] = {
          'version' => ver,
          'source_url' => url,
          'retrieved_at' => retrieved,
          'path' => final_path,
          'filename' => final_name
        }
      end

      meta['retrieved_at'] = retrieved
      meta['domains'] = domains_meta
      meta['active_version'] = unified_version(domains_meta)
      write_active_yml(meta)
      [bundle_paths, meta]
    rescue StandardError => e
      warn "MitreVersionResolver network fetch failed: #{e.message}"
      [nil, meta]
    end

    def write_active_yml(meta)
      payload = {
        'retrieved_at' => meta['retrieved_at'],
        'active_version' => meta['active_version'],
        'domains' => meta['domains']
      }
      FileUtils.mkdir_p(CACHE_DIR)
      File.write(ACTIVE_FILE, YAML.dump(payload))
    end

    def resolve_legacy_enterprise_only(meta)
      legacy = File.join(CACHE_DIR, 'enterprise-attack.json')
      return [nil, meta] unless File.exist?(legacy) && File.size(legacy) > 100_000

      begin
        ver = MitreCommon.attack_version_from_bundle(JSON.parse(File.read(legacy)))
      rescue StandardError
        ver = nil
      end

      bundle_paths = { 'enterprise' => legacy }
      meta['domains'] ||= {}
      meta['domains']['enterprise'] = {
        'version' => ver,
        'source_url' => MitreCommon.bundle_url('enterprise'),
        'path' => legacy
      }
      meta['active_version'] = ver
      [bundle_paths, meta]
    end

    def download_url(url, path)
      uri = URI.parse(url)
      Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == 'https', read_timeout: 180, open_timeout: 30) do |http|
        req = Net::HTTP::Get.new(uri)
        res = http.request(req)
        raise "HTTP #{res.code} for #{url}" unless res.is_a?(Net::HTTPSuccess)

        File.binwrite(path, res.body)
      end
    end
  end
end
