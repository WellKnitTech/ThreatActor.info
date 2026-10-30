# frozen_string_literal: true

require 'json'
require 'set'
require 'time'
require 'uri'
require 'yaml'

# Shared helpers for daily security-news fetch, filter, dedup, and actor matching.
module NewsFeed
  OUTPUT_FILE = '_data/news_feed.yml'
  ACTORS_GLOB = '_data/actors/*.yml'
  WINDOW_DAYS = 14
  MAX_ITEMS = 80
  MAX_PER_ACTOR = 5
  MAX_PER_FEED = 15

  # Native security/intel sources keep items that pass a light relevance gate.
  # General tech sources must match a stricter security-relevance pattern.
  RSS_FEEDS = [
    { name: 'BleepingComputer', url: 'https://www.bleepingcomputer.com/feed/', weight: 2, category: :security },
    { name: 'The Hacker News', url: 'https://feeds.feedburner.com/TheHackersNews', weight: 2, category: :security },
    { name: 'KrebsOnSecurity', url: 'https://krebsonsecurity.com/feed/', weight: 2, category: :security },
    { name: 'DarkReading', url: 'https://www.darkreading.com/rss.xml', weight: 2, category: :security },
    { name: 'SecurityWeek', url: 'https://www.securityweek.com/feed', weight: 2, category: :security },
    { name: 'The Record', url: 'https://therecord.media/feed', weight: 2, category: :security },
    { name: 'CISA Advisories', url: 'https://www.cisa.gov/cybersecurity-advisories/all.xml', weight: 2, category: :security },
    { name: 'Microsoft Security', url: 'https://www.microsoft.com/en-us/security/blog/feed/', weight: 2, category: :security },
    { name: 'Cisco Talos', url: 'https://blog.talosintelligence.com/rss/', weight: 2, category: :security },
    { name: 'Securelist', url: 'https://securelist.com/feed/', weight: 2, category: :security },
    { name: 'Malwarebytes', url: 'https://www.malwarebytes.com/blog/feed', weight: 1, category: :security },
    { name: 'Unit 42', url: 'https://unit42.paloaltonetworks.com/feed/', weight: 2, category: :security },
    { name: 'Palo Alto Networks', url: 'https://blog.paloaltonetworks.com/feed/', weight: 1, category: :security },
    { name: 'Elastic Security', url: 'https://www.elastic.co/security-labs/rss/feed.xml', weight: 2, category: :security },
    { name: 'Cloudflare', url: 'https://blog.cloudflare.com/rss/', weight: 1, category: :security },
    { name: 'Check Point', url: 'https://blog.checkpoint.com/feed/', weight: 1, category: :security },
    { name: 'SentinelOne', url: 'https://www.sentinelone.com/blog/feed/', weight: 1, category: :security },
    { name: 'Rapid7', url: 'https://www.rapid7.com/blog/rss', weight: 1, category: :security },
    # General tech — kept for breach/security coverage but filtered strictly.
    { name: 'Ars Technica', url: 'https://feeds.arstechnica.com/arstechnica/security', weight: 1, category: :general },
    { name: 'TechCrunch', url: 'https://techcrunch.com/tag/security/feed/', weight: 1, category: :general },
    { name: 'Wired Security', url: 'https://www.wired.com/feed/category/security/latest/rss', weight: 1, category: :general }
  ].freeze

  # High-signal curated aliases. Tools (Cobalt Strike, Mimikatz, etc.) are intentionally omitted.
  CURATED_KEYWORDS = {
    'APT28' => ['apt28', 'fancy bear', 'sofacy', 'pawn storm', 'sednit', 'strontium', 'forest blizzard'],
    'APT29' => ['apt29', 'cozy bear', 'the duke', 'nobelium', 'yttrium', 'midnight blizzard'],
    'Sandworm' => ['sandworm', 'voodoo bear', 'industroyer', 'notpetya'],
    'Turla' => ['turla', 'waterbug', 'venomous bear'],
    'APT41' => ['apt41', 'winnti', 'wicked panda'],
    'APT10' => ['apt10', 'menupass', 'stone panda'],
    'APT17' => ['apt17', 'hidden lynx', 'aurora panda'],
    'APT33' => ['apt33', 'elfin', 'magnallium'],
    'MuddyWater' => ['muddywater', 'seedworm', 'static kitten', 'muddy water'],
    'OilRig' => ['oilrig', 'cobalt gypsy', 'twisted kitten'],
    'Lazarus' => ['lazarus', 'hidden cobra', 'labyrinth chollima'],
    'Kimsuky' => ['kimsuky', 'thallium', 'velvet chollima'],
    'LockBit' => ['lockbit', 'lockbit 3.0', 'lockbit ransomware'],
    'Conti' => ['conti', 'conti ransomware', 'wizard spider'],
    'REvil' => ['revil', 'sodinokibi'],
    'BlackCat' => ['alphv', 'blackcat ransomware'],
    'Clop' => ['clop ransomware', 'cl0p'],
    'Akira' => ['akira ransomware'],
    'BlackBasta' => ['blackbasta', 'black basta', 'basta ransomware'],
    'Royal' => ['royal ransomware'],
    'Play' => ['play ransomware'],
    'Rhysida' => ['rhysida'],
    'Cuba' => ['cuba ransomware'],
    'FIN7' => ['fin7', 'carbanak', 'carbon spider'],
    'TA505' => ['ta505'],
    'Emotet' => ['emotet'],
    'TrickBot' => ['trickbot'],
    'Qakbot' => ['qakbot', 'qbot', 'quakbot'],
    'IcedID' => ['icedid', 'bokbot'],
    'Mustang Panda' => ['mustang panda'],
    'Patchwork' => ['patchwork', 'dropping eagle'],
    'Sidewinder' => ['sidewinder']
  }.freeze

  # Short/common aliases that create false positives via substring or English-word hits.
  # Includes frequent RansomLook/MISP single-token names that are ordinary English words.
  AMBIGUOUS_ALIASES = %w[
    r pl ra lv dn tk bb php rns oct bud ank oni cry sea inc inc. one mini core first
    aware hive ghost light shadow root safe global rapid judge clock frog frag boom
    frozen play cuba trojan ruby android desktop encrypt payment evolution revolution
    quantum nova lurk hunt hunters hacked korean telegram zinc barium snake duke
    royal knight gold ionic silent magic chaos homeland lock key dark black white
    blue red green rain fire storm moon sun star wolf bear eagle shark spider
    phantom spectre spectre specter venom poison virus danger danger hunter target
    alpha beta gamma delta omega prime matrix crypto locker locker crypt
    empire empire agency agency security security network network system system
    service service group group team team family family nation nation
    action train covert python rector russian chinese korean iranian syrian
    american european asian african japanese german french british israeli
    ukraine ukrainian poland polish taiwan taiwanese vietnam vietnamese
  ].freeze

  CODE_LIKE = /\A(?:apt|ta|fin|unc|apt-?)?\d{1,5}[a-z]?\z/i
  CVE_RE = /\bCVE-\d{4}-\d{4,7}\b/i
  SECURITY_RE = /\b(?:
    ransomware|malware|phishing|spyware|trojan|backdoor|botnet|rootkit|
    vulnerability|vulnerabilities|exploit|zero[\s-]?day|0day|cve-\d{4}|
    breach|cyberattack|cyber[\s-]?attack|threat\s+actor|apt\d*|nation[\s-]?state|
    ransomware|extortion|data\s+leak|credential|infostealer|stealer|
    cybersecurity|cyber\s+security|infosec|hackers?|hacking|compromised|
    advisory|kev\b|patch\b|remote\s+code|rce\b|privilege\s+escalation|
    ddos|botnet|c2\b|command[\s-]and[\s-]control|ioc\b|indicator|
    sandbox(?:es)?|zero[\s-]?day|supply[\s-]chain
  )\b/ix

  # Non-security fluff that still appears on otherwise-good security feeds.
  FLUFF_RE = /\b(?:
    usage\s+limits?|headphones?\s+sale|robotaxis?|spaceplane|death\s+clock|
    magic\s+quadrant|gartner|earnings|stock\s+price|prime\s+video|
    religious\s+exemption|booming\s+cloud|weekly\s+recap
  )\b/ix

  TRACKING_PARAMS = %w[
    utm_source utm_medium utm_campaign utm_term utm_content utm_id
    fbclid gclid mc_cid mc_eid ref source
  ].freeze

  module_function

  def normalize_keyword(keyword)
    keyword.to_s.strip.downcase.gsub(/\s+/, ' ')
  end

  def ambiguous_alias?(keyword)
    AMBIGUOUS_ALIASES.include?(normalize_keyword(keyword))
  end

  def usable_alias?(keyword, curated: false)
    kw = normalize_keyword(keyword)
    return false if kw.empty?
    return false if kw.length < 3
    return false if ambiguous_alias?(kw)
    return true if curated
    return true if kw.include?(' ')
    return true if CODE_LIKE.match?(kw)
    # Single-token auto aliases must be reasonably distinctive; common words are
    # blocked via AMBIGUOUS_ALIASES even when long (e.g. homeland, silent).
    return true if kw.length >= 6
    false
  end

  def word_boundary_pattern(keyword)
    kw = normalize_keyword(keyword)
    escaped = Regexp.escape(kw).gsub('\\ ', '[[:space:]]+')
    Regexp.new("(?<![[:alnum:]])#{escaped}(?![[:alnum:]])", Regexp::IGNORECASE)
  end

  def text_match?(haystack, keyword)
    return false if haystack.to_s.empty?
    word_boundary_pattern(keyword).match?(haystack)
  end

  def parse_time(value)
    return nil if value.nil? || value.to_s.strip.empty?
    return value.utc if value.is_a?(Time)
    return value.to_time.utc if value.respond_to?(:to_time)

    Time.parse(value.to_s).utc
  rescue ArgumentError, TypeError
    nil
  end

  def within_window?(value, now: Time.now.utc, days: WINDOW_DAYS)
    ts = parse_time(value)
    return false unless ts

    ts >= (now - (days * 24 * 60 * 60)) && ts <= (now + (2 * 60 * 60))
  end

  def canonicalize_url(url)
    uri = URI.parse(url.to_s.strip)
    return url.to_s.strip if uri.scheme.nil? || uri.host.nil?

    uri.scheme = uri.scheme.downcase
    uri.host = uri.host.downcase.sub(/\Awww\./, '')
    uri.fragment = nil
    if uri.query
      params = URI.decode_www_form(uri.query).reject { |k, _| TRACKING_PARAMS.include?(k.downcase) }
      uri.query = params.empty? ? nil : URI.encode_www_form(params)
    end
    path = uri.path.to_s
    path = path.sub(%r{/\z}, '') if path.length > 1
    uri.path = path.empty? ? '/' : path
    uri.to_s
  rescue URI::InvalidURIError
    url.to_s.strip
  end

  def normalize_title(title)
    title.to_s.downcase.gsub(/[^a-z0-9\s]/, ' ').gsub(/\s+/, ' ').strip
  end

  def title_similarity(a, b)
    ta = normalize_title(a).split
    tb = normalize_title(b).split
    return 0.0 if ta.empty? || tb.empty?

    overlap = (ta & tb).size
    overlap.to_f / [ta.size, tb.size].max
  end

  def extract_cves(text)
    text.to_s.scan(CVE_RE).map { |cve| cve.upcase }.uniq
  end

  def security_relevant?(title, category:)
    text = title.to_s
    return false if text.strip.empty?
    return false if FLUFF_RE.match?(text)

    case category.to_sym
    when :security
      # Vendor/security feeds still mix product posts; require a security signal.
      SECURITY_RE.match?(text) || text.match?(/\b(?:cisa|kev|apt\d+|ransomware|malware|phish|breach|exploit|vulnerab|threat)\b/i)
    else
      SECURITY_RE.match?(text)
    end
  end

  def load_actor_records(actors_glob: ACTORS_GLOB)
    Dir.glob(actors_glob).sort.filter_map do |path|
      actor = YAML.safe_load(File.read(path), permitted_classes: [Date, Time], aliases: false)
      next unless actor.is_a?(Hash)

      name = actor['name'].to_s.strip
      next if name.empty?

      {
        'name' => name,
        'url' => actor['url'].to_s,
        'aliases' => Array(actor['aliases']).map { |a| a.to_s.strip }.reject(&:empty?)
      }
    rescue Psych::SyntaxError
      nil
    end
  end

  def build_keyword_index(actors = load_actor_records)
    # keyword -> [{name:, url:, alias:}, ...]
    index = Hash.new { |h, k| h[k] = [] }

    CURATED_KEYWORDS.each do |actor_name, words|
      url = actors.find { |a| a['name'].casecmp?(actor_name) }&.dig('url').to_s
      words.each do |word|
        next unless usable_alias?(word, curated: true)

        index[normalize_keyword(word)] << { name: actor_name, url: url, alias: normalize_keyword(word) }
      end
    end

    actors.each do |actor|
      candidates = [actor['name'], *actor['aliases']]
      candidates.each do |raw|
        next unless usable_alias?(raw, curated: false)

        kw = normalize_keyword(raw)
        index[kw] << { name: actor['name'], url: actor['url'], alias: kw }
      end
    end

    index.transform_values(&:uniq)
  end

  def match_actors(title, keyword_index = build_keyword_index)
    text = title.to_s
    matched = {}

    keyword_index.each do |keyword, entries|
      next unless text_match?(text, keyword)

      entries.each do |entry|
        key = entry[:name]
        matched[key] ||= entry
      end
    end

    matched.values
  end

  def deduplicate_items(items)
    sorted = items.sort_by { |i| parse_time(i[:date]) || Time.at(0) }.reverse
    kept = []

    sorted.each do |item|
      canonical = item[:canonical_url] || canonicalize_url(item[:link])
      duplicate = kept.find do |other|
        other_canonical = other[:canonical_url] || canonicalize_url(other[:link])
        next true if other_canonical == canonical

        title_similarity(other[:title], item[:title]) >= 0.9
      end

      if duplicate
        # Prefer higher-weight / earlier-listed security sources.
        if (item[:weight] || 1) > (duplicate[:weight] || 1)
          kept[kept.index(duplicate)] = item.merge(canonical_url: canonical)
        end
        next
      end

      kept << item.merge(canonical_url: canonical)
    end

    kept
  end

  def enrich_item(item, keyword_index)
    title = item[:title].to_s
    cves = extract_cves(title)
    actors = match_actors(title, keyword_index)
    tags = []
    tags << 'cve' if cves.any?
    tags << 'ransomware' if title.match?(/\bransomware\b/i)
    tags << 'apt' if title.match?(/\bapt\d*\b/i)
    tags << 'breach' if title.match?(/\bbreach|data\s+leak|extortion\b/i)

    item.merge(
      canonical_url: canonicalize_url(item[:link]),
      date: (parse_time(item[:date]) || Time.now.utc).iso8601,
      cves: cves,
      tags: tags,
      actors: actors.map { |a| { 'name' => a[:name], 'url' => a[:url], 'matched_alias' => a[:alias] } }
    )
  end

  def build_actor_news(items)
    actor_news = Hash.new { |h, k| h[k] = [] }

    items.each do |item|
      Array(item[:actors] || item['actors']).each do |actor|
        name = actor.is_a?(Hash) ? (actor[:name] || actor['name']) : actor.to_s
        next if name.to_s.empty?

        actor_news[name] << {
          'title' => item[:title] || item['title'],
          'link' => item[:link] || item['link'],
          'date' => item[:date] || item['date'],
          'source' => item[:source] || item['source'],
          'cves' => item[:cves] || item['cves'] || [],
          'tags' => item[:tags] || item['tags'] || []
        }
      end
    end

    actor_news.transform_values { |list| list.first(MAX_PER_ACTOR) }
  end

  def serialize_items(items)
    items.map do |item|
      {
        'title' => item[:title] || item['title'],
        'link' => item[:link] || item['link'],
        'canonical_url' => item[:canonical_url] || item['canonical_url'],
        'date' => item[:date] || item['date'],
        'source' => item[:source] || item['source'],
        'weight' => item[:weight] || item['weight'] || 1,
        'cves' => item[:cves] || item['cves'] || [],
        'tags' => item[:tags] || item['tags'] || [],
        'actors' => (item[:actors] || item['actors'] || []).map do |actor|
          if actor.is_a?(Hash)
            {
              'name' => actor[:name] || actor['name'],
              'url' => actor[:url] || actor['url'],
              'matched_alias' => actor[:matched_alias] || actor['matched_alias']
            }
          else
            { 'name' => actor.to_s, 'url' => '', 'matched_alias' => '' }
          end
        end
      }
    end
  end

  def build_output(items, source_health:, sources: RSS_FEEDS.map { |f| f[:name] }, updated: Time.now.utc)
    enriched_source = items
    {
      'updated' => updated.iso8601,
      'window_days' => WINDOW_DAYS,
      'sources' => sources,
      'source_health' => source_health,
      'items' => serialize_items(enriched_source),
      'actor_news' => build_actor_news(enriched_source)
    }
  end

  def process_items(raw_items, keyword_index: build_keyword_index, now: Time.now.utc, window_days: WINDOW_DAYS)
    filtered = raw_items.select do |item|
      category = item[:category] || :security
      within_window?(item[:date], now: now, days: window_days) &&
        security_relevant?(item[:title], category: category)
    end

    enriched = filtered.map { |item| enrich_item(item, keyword_index) }
    deduplicate_items(enriched).first(MAX_ITEMS)
  end
end
