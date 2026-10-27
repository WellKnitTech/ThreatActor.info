# frozen_string_literal: true

require 'minitest/autorun'
require 'tmpdir'
require 'fileutils'
require_relative '../scripts/actor_store'

class ActorStoreDataPathTest < Minitest::Test
  def test_load_all_attaches_data_path_without_serializing_it
    Dir.mktmpdir do |dir|
      actors_dir = File.join(dir, '_data', 'actors')
      FileUtils.mkdir_p(actors_dir)
      path = File.join(actors_dir, 'demo.yml')
      File.write(path, <<~YAML)
        name: "Demo"
        aliases: ["Demo"]
        description: "demo"
        url: "/demo"
      YAML

      Dir.chdir(dir) do
        actors = ActorStore.load_all
        assert_equal 1, actors.length
        assert_equal '_data/actors/demo.yml', actors.first['__data_path']
        assert_equal '_threat_actors/demo.md', actors.first['__page_path']

        serialized = ActorStore.serialize_actor(actors.first)
        refute_includes serialized, '__data_path'
        refute_includes serialized, '__page_path'
      end
    end
  end
end
