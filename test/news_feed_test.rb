# frozen_string_literal: true

require 'minitest/autorun'
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
      { 'name' => 'Hive', 'url' => '/hive', 'aliases' => ['Hive'] },
      { 'name' => 'Play', 'url' => '/play', 'aliases' => ['Play'] },
      { 'name' => 'Silent', 'url' => '/silent', 'aliases' => ['Silent'] },
      { 'name' => 'Magic', 'url' => '/magic', 'aliases' => ['Magic'] },
      { 'name' => 'Chaos', 'url' => '/chaos', 'aliases' => ['Chaos'] },
      { 'name' => 'Homeland', 'url' => '/homeland', 'aliases' => ['Homeland'] },
      { 'name' => 'Volt Typhoon', 'url' => '/volt-typhoon', 'aliases' => ['Volt Typhoon'] }
    ]
    @index = NewsFeed.build_keyword_index(@actors)
  end

  def test_short_aliases_are_not_indexed
    %w[pl r cry sea inc hive play silent magic chaos homeland].each do |keyword|
      assert_nil @index[keyword], "expected #{keyword.inspect} to be omitted from the index"
    end
  end

  def test_strong_aliases_are_indexed
    %w[lockbit apt28 fancy\ bear syrian\ electronic\ army inc\ ransom].each do |keyword|
      refute_nil @index[keyword], "expected #{keyword.inspect} to be indexed"
      refute_empty @index[keyword]
    end
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
      'Hacker stole personnel data about thousands of Homeland Security employees' => []
    }

    samples.each do |title, expected|
      names = NewsFeed.match_actors(title, @index).map { |m| m[:name] }
      assert_equal expected, names, "unexpected matches for #{title.inspect}: #{names.inspect}"
    end
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

  def test_deduplicate_by_canonical_url_and_title_similarity
    items = [
      { title: 'LockBit hits hospital', link: 'https://www.example.com/a?utm_source=1', date: '2026-10-30T10:00:00Z', source: 'A', weight: 1 },
      { title: 'LockBit hits hospital', link: 'https://example.com/a', date: '2026-10-30T11:00:00Z', source: 'B', weight: 2 },
      { title: 'Completely different story about DNS', link: 'https://example.com/b', date: '2026-10-30T12:00:00Z', source: 'C', weight: 1 }
    ]

    deduped = NewsFeed.deduplicate_items(items)
    assert_equal 2, deduped.size
    assert_equal 'B', deduped[1][:source] unless deduped[0][:source] == 'B'
    assert(deduped.any? { |i| i[:source] == 'B' })
  end

  def test_date_window_and_relevance_filters
    now = Time.parse('2026-10-30T12:00:00Z')
    raw = [
      { title: 'LockBit ransomware attack on city', link: 'https://ex.test/1', date: '2026-10-29T00:00:00Z', source: 'S', weight: 2, category: :security },
      { title: 'Waymo taps Toyota to supply robotaxis', link: 'https://ex.test/2', date: '2026-10-29T00:00:00Z', source: 'TechCrunch', weight: 1, category: :general },
      { title: 'Old LockBit story', link: 'https://ex.test/3', date: '2026-09-01T00:00:00Z', source: 'S', weight: 2, category: :security },
      { title: 'Hospital discloses ransomware breach', link: 'https://ex.test/4', date: '2026-10-28T00:00:00Z', source: 'TechCrunch', weight: 1, category: :general }
    ]

    processed = NewsFeed.process_items(raw, keyword_index: @index, now: now)
    titles = processed.map { |i| i[:title] }
    assert_includes titles, 'LockBit ransomware attack on city'
    assert_includes titles, 'Hospital discloses ransomware breach'
    refute_includes titles, 'Waymo taps Toyota to supply robotaxis'
    refute_includes titles, 'Old LockBit story'
  end

  def test_extract_cves_and_output_schema
    now = Time.parse('2026-10-30T12:00:00Z')
    raw = [
      {
        title: 'CISA adds CVE-2026-12345 and CVE-2026-99999 to KEV after LockBit abuse',
        link: 'https://ex.test/cve',
        date: '2026-10-29T00:00:00Z',
        source: 'CISA Advisories',
        weight: 2,
        category: :security
      }
    ]
    processed = NewsFeed.process_items(raw, keyword_index: @index, now: now)
    output = NewsFeed.build_output(processed, source_health: { 'CISA Advisories' => { 'ok' => true, 'items' => 1 } }, updated: now)

    assert_equal 14, output['window_days']
    assert_equal ['CVE-2026-12345', 'CVE-2026-99999'], output['items'].first['cves']
    assert_includes output['items'].first['actors'].map { |a| a['name'] }, 'LockBit'
    assert output['actor_news'].key?('LockBit')
    assert output['actor_news']['LockBit'].first.key?('cves')
  end
end
