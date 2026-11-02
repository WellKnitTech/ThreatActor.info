# frozen_string_literal: true

require 'minitest/autorun'
require 'fileutils'
require 'json'
require 'tmpdir'
require 'open3'
require 'rbconfig'

class GeneratePagesNewsOnlyTest < Minitest::Test
  SCRIPT = File.expand_path('../scripts/generate-pages.rb', __dir__)

  def test_news_only_preserves_references_on_weekly_style_page
    Dir.mktmpdir('news-only-') do |dir|
      actors_dir = File.join(dir, '_data', 'actors')
      pages_dir = File.join(dir, '_threat_actors')
      FileUtils.mkdir_p(actors_dir)
      FileUtils.mkdir_p(pages_dir)
      FileUtils.mkdir_p(File.join(dir, '_data'))

      File.write(File.join(actors_dir, 'oilrig.yml'), <<~YAML)
        name: "OilRig"
        aliases: ["OilRig", "APT34"]
        description: "Iranian threat group."
        url: "/oilrig"
        external_url: "https://attack.mitre.org/groups/G0049"
      YAML

      weekly_refs = <<~REFS
        [1] [mitre-attack](https://attack.mitre.org/groups/G0049)
        [13] [Check Point APT34 April 2021](https://research.checkpoint.com/2021/irans-apt34-returns-with-an-updated-arsenal/)
           Check Point. (2021, April 8). Iran’s APT34 Returns with an Updated Arsenal.
      REFS

      File.write(File.join(pages_dir, 'oilrig.md'), <<~PAGE)
        ---
        layout: threat_actor
        title: "OilRig"
        aliases: ["OilRig"]
        description: "Iranian threat group."
        permalink: /oilrig/
        ---

        ## Introduction
        Iranian threat group.

        ## References
        #{weekly_refs}
        ## Attribution and Evidence
        *Pending*
      PAGE

      File.write(File.join(dir, '_data', 'news_feed.yml'), JSON.pretty_generate({
        'actor_news' => {
          'OilRig' => [
            {
              'title' => 'OilRig hits energy sector',
              'link' => 'https://example.test/oilrig-news',
              'date' => '2026-11-02T00:00:00Z',
              'source' => 'The Hacker News',
              'cves' => [],
              'tags' => []
            }
          ]
        }
      }))

      # Empty references cache mimics the daily-news failure mode.
      File.write(File.join(dir, '_data', 'references.json'), '{}')

      # Run generate-pages in the temp tree by chdir.
      env = { 'VERBOSE' => nil }
      cmd = [RbConfig.ruby, SCRIPT, '--news-only', '--actor', 'OilRig']
      stdout, stderr, status = Open3.capture3(env, *cmd, chdir: dir)
      assert status.success?, "news-only failed: #{stderr}\n#{stdout}"

      updated = File.read(File.join(pages_dir, 'oilrig.md'))
      refs = updated[/^## References\n(.*?)(?=^## |\z)/m, 1]
      refute_nil refs
      assert_includes refs, 'Check Point APT34 April 2021'
      assert_includes refs, 'mitre-attack'
      assert_includes updated, '## Recent News'
      assert_includes updated, 'OilRig hits energy sector'

      # Full --force with empty cache must still preserve richer existing refs.
      stdout2, stderr2, status2 = Open3.capture3(env, RbConfig.ruby, SCRIPT, '--force', '--actor', 'OilRig', chdir: dir)
      assert status2.success?, "force failed: #{stderr2}\n#{stdout2}"
      forced = File.read(File.join(pages_dir, 'oilrig.md'))
      refs2 = forced[/^## References\n(.*?)(?=^## |\z)/m, 1]
      assert_includes refs2, 'Check Point APT34 April 2021'
    end
  end
end
