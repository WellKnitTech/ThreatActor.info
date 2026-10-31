# frozen_string_literal: true

require 'cgi'
require 'fileutils'
require 'json'
require 'set'
require 'time'
require 'uri'
require 'yaml'

# Shared helpers for daily security-news fetch, filter, dedup, actor matching,
# and additive archive storage.
module NewsFeed
  OUTPUT_FILE = '_data/news_feed.yml'
  ARCHIVE_DIR = 'data/news/archive'
  ACTORS_GLOB = '_data/actors/*.yml'

  # Window still decides which freshly fetched feed items are candidates.
  # It is NOT a deletion rule — stored archive items persist forever.
  WINDOW_DAYS = 14
  DISPLAY_ITEMS = 100
  MAX_PER_ACTOR_DISPLAY = 8
  MAX_PER_FEED = 15
  FEED_DEADLINE_SECONDS = 45
  OPEN_TIMEOUT = 8
  READ_TIMEOUT = 12

  BROWSER_UA = 'Mozilla/5.0 (compatible; ThreatActorInfo/1.0; +https://threatactor.info) ' \
               'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'

  # Native security/intel sources keep items that pass a light relevance gate.
  # General tech sources must match a stricter security-relevance pattern.
  RSS_FEEDS = [
    { name: 'BleepingComputer', url: 'https://www.bleepingcomputer.com/feed/', weight: 2, category: :security },
    { name: 'The Hacker News', url: 'https://feeds.feedburner.com/TheHackersNews', weight: 2, category: :security },
    { name: 'KrebsOnSecurity', url: 'https://krebsonsecurity.com/feed/', weight: 2, category: :security },
    { name: 'DarkReading', url: 'https://www.darkreading.com/rss.xml', weight: 2, category: :security },
    # SecurityWeek has historically 403'd bot UAs; kept with browser UA + health tracking.
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
    # Feedburner /feeds.arstechnica.com/arstechnica/security went 404; current path is /security/rss.
    { name: 'Ars Technica', url: 'https://arstechnica.com/security/rss', weight: 1, category: :general },
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
  # These are never indexed.
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
    unknown fake common simple special general private public official personal
    national international local modern digital virtual physical critical important
    standard advanced basic primary secondary major minor large small new old
    last best worst true false real open closed free paid soft hard
  ].freeze

  # Distinctive product/vendor/platform names that also appear as ransomware or actor
  # labels. Indexed, but a title match requires nearby group-identity context
  # (e.g. "Zimbra ransomware") — not merely mentioning the product.
  PRODUCT_VENDOR_ALIASES = %w[
    zimbra microsoft google apple cisco vmware oracle adobe amazon aws azure
    facebook meta twitter linkedin github gitlab slack zoom nokia samsung intel
    amd nvidia exchange outlook sharepoint wordpress joomla drupal jenkins
    elasticsearch elastic kibana splunk nginx apache mysql postgres mongodb redis
    docker kubernetes ubuntu windows linux android ios chrome firefox sophos crowdstrike
    fortinet juniper aruba akamai cloudflare qualys tenable nessus telegram discord
    whatsapp signal dropbox box icloud office365
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

  def product_vendor_alias?(keyword)
    PRODUCT_VENDOR_ALIASES.include?(normalize_keyword(keyword))
  end

  # Product/vendor aliases and any future explicit stoplist entries require
  # group-identity context. Coined actor tokens (LockBit, GhostAction,
  # ShinyHunters) are not in PRODUCT_VENDOR_ALIASES and match freely.
  # Ordinary English words live in AMBIGUOUS_ALIASES and are never indexed.
  def context_required_alias?(keyword, curated: false)
    return false if curated

    kw = normalize_keyword(keyword)
    return false if kw.include?(' ')
    return false if CODE_LIKE.match?(kw)

    product_vendor_alias?(kw)
  end

  def usable_alias?(keyword, curated: false)
    kw = normalize_keyword(keyword)
    return false if kw.empty?
    return false if kw.length < 3
    return false if ambiguous_alias?(kw)
    return true if curated
    return true if kw.include?(' ')
    return true if CODE_LIKE.match?(kw)
    # Product/vendor aliases are indexed but matched with extra context.
    return true if product_vendor_alias?(kw)
    # Single-token auto aliases must be reasonably distinctive.
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

  # Require the alias to appear as a named group/family, not merely as a product
  # or English adjective (blocks "Unknown APT", "Zimbra log file").
  def actor_context_match?(haystack, keyword)
    kw = Regexp.escape(normalize_keyword(keyword)).gsub('\\ ', '[[:space:]]+')
    patterns = [
      /\b#{kw}[[:space:]]+ransomware\b/i,
      /\b#{kw}[[:space:]]+(?:ransomware[[:space:]]+)?(?:group|gang|crew|family|operation)\b/i,
      /\b(?:ransomware|threat)[[:space:]]+(?:group|gang|crew|actor)[[:space:]]+#{kw}\b/i,
      /\b#{kw}[[:space:]]+(?:threat[[:space:]]+)?actor\b/i,
      /\bransomware[[:space:]]+(?:group|gang|crew|family)?[[:space:]]*#{kw}\b/i
    ]
    patterns.any? { |re| re.match?(haystack.to_s) }
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

  def month_key(value)
    ts = parse_time(value)
    return 'unknown' unless ts

    ts.strftime('%Y-%m')
  end

  # Only allow http(s) links with a host. Rejects javascript:, data:, etc.
  def safe_http_url?(url)
    uri = URI.parse(url.to_s.strip)
    return false unless uri.is_a?(URI::HTTP)
    return false if uri.host.to_s.strip.empty?

    %w[http https].include?(uri.scheme.to_s.downcase)
  rescue URI::InvalidURIError, ArgumentError
    false
  end

  def canonicalize_url(url)
    return nil unless safe_http_url?(url)

    uri = URI.parse(url.to_s.strip)
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
  rescue URI::InvalidURIError, ArgumentError
    nil
  end

  # Strip markup from feed-supplied text so HTML never lands in stored JSON/markdown.
  # Templates still HTML-escape on render for defense in depth.
  def sanitize_feed_text(text)
    value = CGI.unescapeHTML(text.to_s)
    value = value.gsub(/<!--.*?-->/m, ' ')
    value = value.gsub(/<[^>]*>/, ' ')
    value = value.gsub(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/, '')
    value.gsub(/\s+/, ' ').strip
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
    # keyword -> [{name:, url:, alias:, context_required:}, ...]
    index = Hash.new { |h, k| h[k] = [] }

    CURATED_KEYWORDS.each do |actor_name, words|
      url = actors.find { |a| a['name'].casecmp?(actor_name) }&.dig('url').to_s
      words.each do |word|
        next unless usable_alias?(word, curated: true)

        index[normalize_keyword(word)] << {
          name: actor_name,
          url: url,
          alias: normalize_keyword(word),
          context_required: false
        }
      end
    end

    actors.each do |actor|
      candidates = [actor['name'], *actor['aliases']]
      candidates.each do |raw|
        next unless usable_alias?(raw, curated: false)

        kw = normalize_keyword(raw)
        index[kw] << {
          name: actor['name'],
          url: actor['url'],
          alias: kw,
          context_required: context_required_alias?(raw, curated: false) || product_vendor_alias?(kw)
        }
      end
    end

    index.transform_values(&:uniq)
  end

  def partition_keyword_index(keyword_index)
    single = Hash.new { |h, k| h[k] = [] }
    multi = []
    keyword_index.each do |keyword, entries|
      if keyword.include?(' ')
        multi << [keyword, word_boundary_pattern(keyword), entries]
      else
        single[keyword].concat(entries)
      end
    end
    [single, multi]
  end

  def match_actors(title, keyword_index = build_keyword_index)
    text = title.to_s
    matched = {}

    # Fast path: token lookup for single-word aliases, regex only for multi-word.
    single, multi =
      if keyword_index.is_a?(Hash) && keyword_index.key?(:__single) && keyword_index.key?(:__multi)
        [keyword_index[:__single], keyword_index[:__multi]]
      else
        partition_keyword_index(keyword_index)
      end

    tokens = text.downcase.scan(/[a-z0-9][a-z0-9'+.\-]*/)
    tokens.each do |tok|
      Array(single[tok]).each do |entry|
        if entry[:context_required] || entry['context_required']
          next unless actor_context_match?(text, tok)
        end
        key = entry[:name] || entry['name']
        matched[key] ||= entry
      end
    end

    multi.each do |keyword, pattern, entries|
      next unless pattern.match?(text)

      entries.each do |entry|
        if entry[:context_required] || entry['context_required']
          next unless actor_context_match?(text, keyword)
        end
        key = entry[:name] || entry['name']
        matched[key] ||= entry
      end
    end

    matched.values
  end

  # Build an index pre-partitioned for fast match_actors scans.
  def build_match_index(actors = load_actor_records)
    raw = build_keyword_index(actors)
    single, multi = partition_keyword_index(raw)
    { __single: single, __multi: multi, __raw: raw }
  end

  def sort_items_by_date_desc(items)
    # Stable newest-first ordering (index tiebreak) used after dedup replacement.
    items.each_with_index.sort_by do |item, index|
      timestamp = parse_time(item[:date] || item['date']) || Time.at(0)
      [-timestamp.to_f, index]
    end.map(&:first)
  end

  def deduplicate_items(items)
    sorted = sort_items_by_date_desc(items)
    kept = []

    sorted.each do |item|
      canonical = item[:canonical_url] || item['canonical_url'] || canonicalize_url(item[:link] || item['link'])
      next if canonical.nil? || canonical.empty?

      duplicate = kept.find do |other|
        other_canonical = other[:canonical_url] || other['canonical_url'] || canonicalize_url(other[:link] || other['link'])
        next true if other_canonical == canonical

        title_similarity(other[:title] || other['title'], item[:title] || item['title']) >= 0.9
      end

      if duplicate
        # Prefer higher-weight / earlier-listed security sources.
        item_weight = item[:weight] || item['weight'] || 1
        dup_weight = duplicate[:weight] || duplicate['weight'] || 1
        if item_weight > dup_weight
          kept[kept.index(duplicate)] = symbolize_item(item).merge(canonical_url: canonical)
        end
        next
      end

      kept << symbolize_item(item).merge(canonical_url: canonical)
    end

    # Replacing a duplicate in place can leave an older higher-weight item ahead of
    # a newer unrelated item; restore newest-first before applying limits.
    sort_items_by_date_desc(kept)
  end

  def symbolize_item(item)
    return item if item.is_a?(Hash) && item.key?(:title)

    {
      title: item[:title] || item['title'],
      link: item[:link] || item['link'],
      canonical_url: item[:canonical_url] || item['canonical_url'],
      date: item[:date] || item['date'],
      source: item[:source] || item['source'],
      weight: item[:weight] || item['weight'] || 1,
      category: item[:category] || item['category'] || :security,
      cves: item[:cves] || item['cves'] || [],
      tags: item[:tags] || item['tags'] || [],
      actors: item[:actors] || item['actors'] || []
    }
  end

  def enrich_item(item, keyword_index)
    title = sanitize_feed_text(item[:title] || item['title'])
    source = sanitize_feed_text(item[:source] || item['source'])
    link = (item[:link] || item['link']).to_s.strip
    canonical = canonicalize_url(item[:canonical_url] || item['canonical_url'] || link)
    return nil if title.empty? || canonical.nil?

    cves = extract_cves(title)
    actors = match_actors(title, keyword_index)
    tags = []
    tags << 'cve' if cves.any?
    tags << 'ransomware' if title.match?(/\bransomware\b/i)
    tags << 'apt' if title.match?(/\bapt\d*\b/i)
    tags << 'breach' if title.match?(/\bbreach|data\s+leak|extortion\b/i)

    {
      title: title,
      source: source,
      link: canonical,
      canonical_url: canonical,
      date: (parse_time(item[:date] || item['date']) || Time.now.utc).iso8601,
      weight: item[:weight] || item['weight'] || 1,
      category: item[:category] || item['category'] || :security,
      cves: cves,
      tags: tags,
      actors: actors.map { |a| { 'name' => a[:name] || a['name'], 'url' => a[:url] || a['url'], 'matched_alias' => a[:alias] || a['alias'] } }
    }
  end

  def build_actor_news(items, display_limit: nil)
    # display_limit is retained for callers; actor_news stores the full
    # newest-first accumulation. Pages truncate when rendering.
    _ = display_limit
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

    actor_news.transform_values do |list|
      serialize_items(sort_items_by_date_desc(list.map { |row| symbolize_item(row) })).map do |row|
        row.slice('title', 'link', 'date', 'source', 'cves', 'tags')
      end
    end
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
              'matched_alias' => actor[:matched_alias] || actor['matched_alias'] || actor[:alias] || actor['alias']
            }
          else
            { 'name' => actor.to_s, 'url' => '', 'matched_alias' => '' }
          end
        end
      }
    end
  end

  def archive_path(month)
    File.join(ARCHIVE_DIR, "#{month}.json")
  end

  def ensure_archive_dir!
    FileUtils.mkdir_p(ARCHIVE_DIR)
  end

  def load_json_file(path)
    return nil unless path && File.exist?(path)

    content = File.read(path).strip
    return nil if content.empty?

    if content.start_with?('{') || content.start_with?('[')
      JSON.parse(content)
    else
      YAML.safe_load(content, permitted_classes: [Date, Time], aliases: false)
    end
  rescue JSON::ParserError, Psych::SyntaxError
    nil
  end

  def load_archived_items(archive_dir: ARCHIVE_DIR)
    return [] unless Dir.exist?(archive_dir)

    Dir.glob(File.join(archive_dir, '*.json')).sort.flat_map do |path|
      data = load_json_file(path)
      next [] unless data

      rows = data.is_a?(Array) ? data : Array(data['items'])
      rows.map { |row| symbolize_item(row) }
    end
  end

  def load_existing_store(output_file: OUTPUT_FILE, archive_dir: ARCHIVE_DIR)
    archived = load_archived_items(archive_dir: archive_dir)
    current = load_json_file(output_file)
    current_items = current.is_a?(Hash) ? Array(current['items']).map { |row| symbolize_item(row) } : []
    deduplicate_items(archived + current_items)
  end

  def write_monthly_archives!(items, archive_dir: ARCHIVE_DIR)
    FileUtils.mkdir_p(archive_dir)

    by_month = Hash.new { |h, k| h[k] = [] }
    items.each do |item|
      by_month[month_key(item[:date] || item['date'])] << item
    end

    written = []
    by_month.keys.sort.each do |month|
      next if month == 'unknown'

      path = File.join(archive_dir, "#{month}.json")
      payload = {
        'month' => month,
        'item_count' => by_month[month].size,
        'items' => serialize_items(sort_items_by_date_desc(by_month[month]))
      }
      File.write(path, JSON.pretty_generate(payload))
      written << { 'month' => month, 'item_count' => payload['item_count'], 'path' => path }
    end
    written
  end

  def rematch_items(items, keyword_index: build_match_index)
    items.filter_map do |item|
      enrich_item(item, keyword_index)
    end
  end

  def build_output(items, source_health:, sources: RSS_FEEDS.map { |f| f[:name] }, updated: Time.now.utc,
                   archive_months: [], display_limit: DISPLAY_ITEMS)
    sorted = sort_items_by_date_desc(items)
    display_items = sorted.first(display_limit)
    {
      'updated' => updated.iso8601,
      'window_days' => WINDOW_DAYS,
      'display_items' => display_limit,
      'item_count_total' => sorted.size,
      'item_count' => display_items.size,
      'retention' => 'additive_archive',
      'archive_dir' => ARCHIVE_DIR,
      'archive_months' => archive_months,
      'sources' => sources,
      'source_health' => source_health,
      'items' => serialize_items(display_items),
      'actor_news' => build_actor_news(sorted)
    }
  end

  # Process freshly fetched feed items (window + relevance). Does not load archive.
  def process_fresh_items(raw_items, keyword_index: build_keyword_index, now: Time.now.utc, window_days: WINDOW_DAYS)
    filtered = raw_items.select do |item|
      category = item[:category] || item['category'] || :security
      safe_http_url?(item[:link] || item['link']) &&
        within_window?(item[:date] || item['date'], now: now, days: window_days) &&
        security_relevant?(item[:title] || item['title'], category: category)
    end

    filtered.filter_map { |item| enrich_item(item, keyword_index) }
  end

  # Merge fresh candidates into the existing store. Never deletes prior items.
  # Re-applies actor matching to the full corpus so stoplist changes take effect.
  def merge_additive(existing_items, fresh_items, keyword_index: build_match_index)
    combined = deduplicate_items(Array(existing_items) + Array(fresh_items))
    rematched = rematch_items(combined, keyword_index: keyword_index)
    deduplicate_items(rematched)
  end

  # Back-compat wrapper used by older tests: window-filter then cap display size.
  # Prefer process_fresh_items + merge_additive for the daily pipeline.
  def process_items(raw_items, keyword_index: build_keyword_index, now: Time.now.utc, window_days: WINDOW_DAYS)
    process_fresh_items(raw_items, keyword_index: keyword_index, now: now, window_days: window_days)
      .then { |items| sort_items_by_date_desc(items).first(DISPLAY_ITEMS) }
  end

  def drop_feed_on_forbidden?(health_entry)
    return false unless health_entry.is_a?(Hash)

    error = health_entry['error'].to_s
    error.match?(/\b403\b/) || error.downcase.include?('forbidden')
  end
end
