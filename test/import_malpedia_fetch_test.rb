# frozen_string_literal: true

require 'json'
require 'minitest/autorun'
require 'tmpdir'
require 'yaml'
require_relative '../scripts/import-malpedia'

class MalpediaFetchTest < Minitest::Test
  class FakeImporter < MalpediaImporter
    attr_reader :requested_ids

    def initialize(*args)
      super
      @requested_ids = []
    end

    private

    def http_get_json(uri)
      case uri.path
      when '/api/list/actors'
        %w[actor-b actor-a actor-c]
      when '/api/get/actors'
        {
          'Actor B' => { 'country' => 'B' },
          'Actor A' => { 'country' => 'A' },
          'Actor C' => { 'country' => 'C' }
        }
      else
        actor_id = uri.path.split('/').last
        @requested_ids << actor_id
        { 'value' => "Actor #{actor_id.split('-').last.upcase}" }
      end
    end
  end

  def test_fetches_all_details_and_writes_them_in_source_order
    Dir.mktmpdir do |dir|
      importer = FakeImporter.new(['fetch', '--output', dir])
      importer.run

      assert_equal %w[actor-a actor-b actor-c], importer.requested_ids.sort
      assert_equal %w[actor-b actor-a actor-c], JSON.parse(File.read(File.join(dir, 'actor_ids.json')))
      assert_equal %w[actor-b actor-a actor-c], JSON.parse(File.read(File.join(dir, 'actor_details.json'))).keys
      cache = YAML.safe_load(File.read(File.join(dir, 'cache-manifest.yml')), permitted_classes: [], aliases: false)
      assert_equal %w[actor-a actor-b actor-c], cache['record_hashes'].keys.sort
    end
  end
end
