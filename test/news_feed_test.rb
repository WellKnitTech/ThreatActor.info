# frozen_string_literal: true

require 'minitest/autorun'
require 'fileutils'
require 'json'
require 'tmpdir'
require 'time'
require_relative '../scripts/lib/news_feed'

class NewsFeedTest < Minitest::Test
  def setup
    @actors = [
      { 'name' => 'PL', 'url' => '/pl', 'aliases' => ['PL'] },
      { 'name' => 'R', 'url' => '/r', 'aliases' => ['NM3', 'R'] },
      { 'name' => 'CryLocker', 'url' => '/crylocker', 'aliases' => ['Cry', 'CryLocker'] },
      { 'name' => 'Deadeye Jackal', 'url' => '/deadeye-jackal', 'aliases' => ['SEA', 'Deadeye Jackal', 'Syrian Electronic Army'] },
      { 'name' => 'INC Ransom', 'url' => '/apt1032', 'aliases' => ['INC Ransom', 'Inc', 'Inc.', 'INC ransomware'] },
      { 'name' => 'LockBit', 'url' => '/lockbit', 'aliases' => ['LockBit', 'LockBit 3.0'] },
      { 'name' => 'APT28', 'url' => '/apt28', 'aliases' => ['APT28', 'Fancy Bear'] },
      { 'name' => 'APT41', 'url' => '/apt41', 'aliases' => ['APT41'] },
      { 'name' => 'Hive', 'url' => '/hive', 'aliases' => ['Hive'] },
      { 'name' => 'Play', 'url' => '/play', 'aliases' => ['Play'] },
      { 'name' => 'Silent', 'url' => '/silent', 'aliases' => ['Silent'] },
      { 'name' => 'Magic', 'url' => '/magic', 'aliases' => ['Magic'] },
      { 'name' => 'Chaos', 'url' => '/chaos', 'aliases' => ['Chaos'] },
      { 'name' => 'Homeland', 'url' => '/homeland', 'aliases' => ['Homeland'] },
      { 'name' => 'Volt Typhoon', 'url' => '/volt-typhoon', 'aliases' => ['Volt Typhoon'] },
      { 'name' => 'Unknown', 'url' => '/unknown', 'aliases' => ['Unknown'] },
      { 'name' => 'Zimbra', 'url' => '/zimbra', 'aliases' => ['Zimbra'] },
      { 'name' => 'GhostAction', 'url' => '/ghostaction', 'aliases' => ['GhostAction'] },
      { 'name' => 'ShinyHunters', 'url' => '/shinyhunters', 'aliases' => ['ShinyHunters'] }
    ]
    @index = NewsFeed.build_keyword_index(@actors)
  end

  def test_short_aliases_are_not_indexed
    %w[pl r cry sea inc hive play silent magic chaos homeland unknown].each do |keyword|
      assert_nil @index[keyword], "expected #{keyword.inspect} to be omitted from the index"
    end
  end

  def test_strong_aliases_are_indexed
    %w[lockbit apt28 fancy\ bear syrian\ electronic\ army inc\ ransom ghostaction shinyhunters].each do |keyword|
      refute_nil @index[keyword], "expected #{keyword.inspect} to be indexed"
      refute_empty @index[keyword]
    end
  end

  def test_zimbra_is_indexed_but_context_required
    refute_nil @index['zimbra']
    assert @index['zimbra'].any? { |e| e[:context_required] }
  end

  def test_false_positive_titles_do_not_match_ambiguous_actors
    samples = {
      'CISA Adds Actively Exploited GitLab RCE and Cisco Firewall DoS Flaws to KEV' => [],
      'Binance Suffers Security Breach Affecting $6.3 Billion in Assets, Nearly $3 Billion Frozen' => [],
      'Fake ChatGPT and Claude Apps Abuse Signed Executables to Deploy Crypto Miners' => [],
      'As search traffic dries up, Reddit announces it’s shifting to a logged-in experience' => [],
      'Fan-fiction site Archive of Our Own (AO3) could be offline after security incident' => [],
      'Rivian expands joint venture with VW to include AI assistant' => [],
      'Rethinking Cybersecurity Awareness in the AI Era' => [],
      'Palo Alto Networks Named a Leader in the 2026 Gartner Magic Quadrant' => [],
      'Weekly Recap: Supply Chain Chaos and More' => [],
      'Volt Typhoon Used Covert Silent Train Network in Four Zero-Day Exploitation Campaigns' => ['Volt Typhoon'],
      'Hacker stole personnel data about thousands of Homeland Security employees' => [],
      'Unknown APT uses NetamLoader to attack a Win10 OS customized for governments in Asia' => [],
      'How CVE-2026-73570 turns a Zimbra log file into remote code execution' => []
    }

    samples.each do |title, expected|
      names = NewsFeed.match_actors(title, @index).map { |m| m[:name] }
      assert_equal expected, names, "unexpected matches for #{title.inspect}: #{names.inspect}"
    end
  end

  def test_product_alias_matches_with_group_context
    names = NewsFeed.match_actors('Zimbra ransomware group leaks victim data', @index).map { |m| m[:name] }
    assert_includes names, 'Zimbra'
  end

  def test_real_actor_titles_match_with_word_boundaries
    lockbit = NewsFeed.match_actors('LockBit ransomware hits hospital network', @index).map { |m| m[:name] }
    assert_includes lockbit, 'LockBit'

    apt = NewsFeed.match_actors('APT28 Fancy Bear phishing wave targets NATO', @index).map { |m| m[:name] }
    assert_includes apt, 'APT28'

    sea = NewsFeed.match_actors('Syrian Electronic Army claims website defacements', @index).map { |m| m[:name] }
    assert_includes sea, 'Deadeye Jackal'

    inc = NewsFeed.match_actors('INC Ransom threatens to leak healthcare data', @index).map { |m| m[:name] }
    assert_includes inc, 'INC Ransom'

    apt41 = NewsFeed.match_actors('How APT41 revived the BlackLotus bootkit', @index).map { |m| m[:name] }
    assert_includes apt41, 'APT41'

    ghost = NewsFeed.match_actors('GhostAction Hacking Wave Fizzles, but Attackers Lurk on in GitHub', @index).map { |m| m[:name] }
    assert_includes ghost, 'GhostAction'

    shiny = NewsFeed.match_actors('Feds Suspect Ransom Negotiator Ran ShinyHunters Extortion Site', @index).map { |m| m[:name] }
    assert_includes shiny, 'ShinyHunters'
  end

  def test_tokenizer_preserves_punctuation_boundaries
    # Hyphen / possessive must not swallow the actor token during the fast path.
    apt = NewsFeed.match_actors(
      'APT28-Linked HOOKEDGE Backdoor Targets European Government and Diplomatic Organizations',
      @index
    ).map { |m| m[:name] }
    assert_includes apt, 'APT28'

    shiny = NewsFeed.match_actors(
      'ShinyHunters-Exploited Oracle PeopleSoft Zero-Day Turns Out to Be Three Chained Flaws',
      @index
    ).map { |m| m[:name] }
    assert_includes shiny, 'ShinyHunters'

    possessive = NewsFeed.match_actors("LockBit's ransomware affiliate leaks hospital data", @index).map { |m| m[:name] }
    assert_includes possessive, 'LockBit'
  end

  def test_word_boundaries_reject_substring_hits
    refute NewsFeed.text_match?('incident response playbook', 'inc')
    refute NewsFeed.text_match?('crypto miners deployed', 'cry')
    refute NewsFeed.text_match?('search traffic drops', 'sea')
    assert NewsFeed.text_match?('LockBit claims attack', 'lockbit')
  end

  def test_canonicalize_url_strips_tracking_and_www
    url = 'https://WWW.Example.com/path/article/?utm_source=x&utm_medium=y&id=1#frag'
    canonical = NewsFeed.canonicalize_url(url)
    assert_equal 'https://example.com/path/article?id=1', canonical
  end

  def test_sanitize_feed_text_strips_html_payloads
    dirty = '&lt;img src=x onerror=alert(1)&gt; LockBit ransomware hits hospital'
    clean = NewsFeed.sanitize_feed_text(dirty)
    refute_includes clean, '<'
    refute_includes clean, '>'
    refute_match(/onerror/i, clean)
    assert_includes clean, 'LockBit ransomware hits hospital'
  end

  def test_javascript_and_non_http_links_are_rejected
    refute NewsFeed.safe_http_url?('javascript:alert(1)')
    refute NewsFeed.safe_http_url?('data:text/html,<script>alert(1)</script>')
    refute NewsFeed.safe_http_url?('ftp://example.com/a')
    assert_nil NewsFeed.canonicalize_url('javascript:alert(1)')

    now = Time.parse('2026-10-30T12:00:00Z')
    processed = NewsFeed.process_items(
      [
        {
          title: 'LockBit ransomware via javascript link',
          link: 'javascript:alert(1)',
          date: '2026-10-29T00:00:00Z',
          source: 'Evil',
          weight: 2,
          category: :security
        },
        {
          title: 'LockBit ransomware via https link',
          link: 'https://ex.test/ok',
          date: '2026-10-29T00:00:00Z',
          source: 'Good',
          weight: 2,
          category: :security
        }
      ],
      keyword_index: @index,
      now: now
    )

    assert_equal 1, processed.size
    assert_equal 'https://ex.test/ok', processed.first[:link]
    refute_includes processed.map { |i| i[:link] }, 'javascript:alert(1)'
  end

  def test_process_items_strips_html_from_titles_in_output
    now = Time.parse('2026-10-30T12:00:00Z')
    processed = NewsFeed.process_items(
      [
        {
          title: '<img src=x onerror=alert(1)> LockBit ransomware campaign',
          link: 'https://ex.test/xss',
          date: '2026-10-29T00:00:00Z',
          source: '<b>EvilSource</b>',
          weight: 2,
          category: :security
        }
      ],
      keyword_index: @index,
      now: now
    )

    assert_equal 1, processed.size
    refute_includes processed.first[:title], '<'
    refute_match(/onerror/i, processed.first[:title])
    assert_equal 'EvilSource', processed.first[:source]
    output = NewsFeed.build_output(processed, source_health: {}, updated: now)
    refute_includes output['items'].first['title'], '<'
  end

  def test_deduplicate_by_canonical_url_and_title_similarity
    items = [
      { title: 'LockBit hits hospital', link: 'https://www.example.com/a?utm_source=1', date: '2026-10-30T10:00:00Z', source: 'A', weight: 1 },
      { title: 'LockBit hits hospital', link: 'https://example.com/a', date: '2026-10-30T11:00:00Z', source: 'B', weight: 2 },
      { title: 'Completely different story about DNS', link: 'https://example.com/b', date: '2026-10-30T12:00:00Z', source: 'C', weight: 1 }
    ]

    deduped = NewsFeed.deduplicate_items(items)
    assert_equal 2, deduped.size
    assert(deduped.any? { |i| i[:source] == 'B' })
  end

  def test_dedup_replacement_restores_newest_first_order
    items = [
      {
        title: 'LockBit ransomware hits hospital',
        link: 'https://example.com/lockbit',
        date: '2026-10-30T12:00:00Z',
        source: 'LowWeight',
        weight: 1
      },
      {
        title: 'Unrelated DNS malware campaign',
        link: 'https://example.com/dns',
        date: '2026-10-30T11:00:00Z',
        source: 'Mid',
        weight: 1
      },
      {
        title: 'LockBit ransomware hits hospital',
        link: 'https://example.com/lockbit?utm_source=dup',
        date: '2026-10-30T10:00:00Z',
        source: 'HighWeight',
        weight: 3
      }
    ]

    deduped = NewsFeed.deduplicate_items(items)
    assert_equal 2, deduped.size
    assert_equal 'Mid', deduped[0][:source], 'newer unrelated item must stay ahead of older replacement'
    assert_equal 'HighWeight', deduped[1][:source]
    dates = deduped.map { |i| NewsFeed.parse_time(i[:date]) }
    assert dates[0] > dates[1]
  end

  def test_date_window_and_relevance_filters_on_fresh_fetch
    now = Time.parse('2026-10-30T12:00:00Z')
    raw = [
      { title: 'LockBit ransomware attack on city', link: 'https://ex.test/1', date: '2026-10-29T00:00:00Z', source: 'S', weight: 2, category: :security },
      { title: 'Waymo taps Toyota to supply robotaxis', link: 'https://ex.test/2', date: '2026-10-29T00:00:00Z', source: 'TechCrunch', weight: 1, category: :general },
      { title: 'Old LockBit story', link: 'https://ex.test/3', date: '2026-09-01T00:00:00Z', source: 'S', weight: 2, category: :security },
      { title: 'Hospital discloses ransomware breach', link: 'https://ex.test/4', date: '2026-10-28T00:00:00Z', source: 'TechCrunch', weight: 1, category: :general }
    ]

    processed = NewsFeed.process_fresh_items(raw, keyword_index: @index, now: now)
    titles = processed.map { |i| i[:title] }
    assert_includes titles, 'LockBit ransomware attack on city'
    assert_includes titles, 'Hospital discloses ransomware breach'
    refute_includes titles, 'Waymo taps Toyota to supply robotaxis'
    refute_includes titles, 'Old LockBit story'
  end

  def test_additive_merge_never_drops_old_stored_items
    now = Time.parse('2026-10-31T12:00:00Z')
    existing = [
      {
        title: 'Volt Typhoon Used Covert Silent Train Network in Four Zero-Day Exploitation Campaigns',
        link: 'https://ex.test/volt',
        date: '2026-10-28T00:00:00Z',
        source: 'The Hacker News',
        weight: 2,
        category: :security
      },
      {
        title: 'Lazarus Abuses South Korean Security Software to Deploy Malware',
        link: 'https://ex.test/lazarus',
        date: '2026-10-21T00:00:00Z',
        source: 'The Hacker News',
        weight: 2,
        category: :security
      }
    ].map { |item| NewsFeed.enrich_item(item, @index) }

    fresh = NewsFeed.process_fresh_items(
      [
        {
          title: 'LockBit ransomware attack on city',
          link: 'https://ex.test/lockbit-new',
          date: '2026-10-31T00:00:00Z',
          source: 'S',
          weight: 2,
          category: :security
        }
      ],
      keyword_index: @index,
      now: now
    )

    merged = NewsFeed.merge_additive(existing, fresh, keyword_index: @index)
    links = merged.map { |i| i[:link] }
    assert_includes links, 'https://ex.test/volt'
    assert_includes links, 'https://ex.test/lazarus'
    assert_includes links, 'https://ex.test/lockbit-new'
    assert_equal 3, merged.size
  end

  def test_monthly_archives_and_output_schema
    now = Time.parse('2026-10-30T12:00:00Z')
    raw = [
      {
        title: 'CISA adds CVE-2026-12345 and CVE-2026-99999 to KEV after LockBit abuse',
        link: 'https://ex.test/cve',
        date: '2026-10-29T00:00:00Z',
        source: 'CISA Advisories',
        weight: 2,
        category: :security
      },
      {
        title: 'Older LockBit ransomware campaign report',
        link: 'https://ex.test/old',
        date: '2026-09-15T00:00:00Z',
        source: 'S',
        weight: 2,
        category: :security
      }
    ]
    enriched = raw.filter_map { |item| NewsFeed.enrich_item(item, @index) }

    Dir.mktmpdir do |dir|
      archive_dir = File.join(dir, 'archive')
      months = NewsFeed.write_monthly_archives!(enriched, archive_dir: archive_dir)
      assert_equal %w[2026-09 2026-10], months.map { |m| m['month'] }
      assert File.exist?(File.join(archive_dir, '2026-10.json'))
      assert File.exist?(File.join(archive_dir, '2026-09.json'))

      output = NewsFeed.build_output(
        enriched,
        source_health: { 'CISA Advisories' => { 'ok' => true, 'items' => 1 } },
        updated: now,
        archive_months: months,
        display_limit: 1
      )

      assert_equal 14, output['window_days']
      assert_equal 'additive_archive', output['retention']
      assert_equal 2, output['item_count_total']
      assert_equal 1, output['item_count']
      assert_equal 1, output['items'].size
      assert_equal ['CVE-2026-12345', 'CVE-2026-99999'], output['items'].first['cves']
      assert_includes output['items'].first['actors'].map { |a| a['name'] }, 'LockBit'
      assert output['actor_news'].key?('LockBit')
      assert_equal 2, output['actor_news']['LockBit'].size
      assert output['actor_news']['LockBit'].first.key?('cves')
    end
  end

  def test_ars_technica_feed_url_updated
    ars = NewsFeed::RSS_FEEDS.find { |f| f[:name] == 'Ars Technica' }
    refute_nil ars
    assert_equal 'https://arstechnica.com/security/rss', ars[:url]
  end

  def test_feed_deadline_constant_is_bounded
    assert NewsFeed::FEED_DEADLINE_SECONDS.between?(30, 60)
  end

  def test_drop_feed_on_forbidden_helper
    assert NewsFeed.drop_feed_on_forbidden?({ 'ok' => false, 'error' => '403 Forbidden' })
    refute NewsFeed.drop_feed_on_forbidden?({ 'ok' => false, 'error' => '404 Not Found' })
    refute NewsFeed.drop_feed_on_forbidden?({ 'ok' => true })
  end

  def test_browser_ua_is_not_the_old_bot_token
    refute_match(/daily-news\/1\.0\z/, NewsFeed::BROWSER_UA)
    assert_match(/Mozilla\/5\.0/, NewsFeed::BROWSER_UA)
  end
end
