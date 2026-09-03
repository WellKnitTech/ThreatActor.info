# frozen_string_literal: true

require 'minitest/autorun'
require 'tmpdir'
require 'yaml'
require_relative '../scripts/import-misp-galaxy'

class ImportMispGalaxyTest < Minitest::Test
  def test_valid_misp_record_with_backslash_and_quote_produces_valid_front_matter
    importer = MispGalaxyImporter.new([])
    record = {
      'value' => 'Valid Actor',
      'description' => 'Uses C:\\Tools\\Agent and says "quoted".',
      'meta' => { 'synonyms' => ['Actor Alias'], 'country' => 'US' },
      'cluster_name' => 'threat-actor.json',
      'uuid' => 'record-123'
    }
    candidate = importer.send(:convert_misp_actor, record)

    refute_nil candidate
    assert_equal 'Valid Actor', candidate[:name]
    assert_equal 'United States', candidate[:country]

    Dir.mktmpdir('misp-page') do |tmpdir|
      Dir.chdir(tmpdir) do
        Dir.mkdir('_threat_actors')
        importer.send(:create_page_file, candidate)
        page = File.read('_threat_actors/valid-actor.md')
        front_matter = page.split(/^---\s*$/, 3)[1]
        parsed = YAML.safe_load(front_matter, permitted_classes: [], aliases: false)

        assert_equal candidate[:description], parsed['description']
        assert_equal candidate[:aliases], parsed['aliases']
      end
    end
  end
end