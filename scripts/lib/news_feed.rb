# frozen_string_literal: true

require 'cgi'
require 'fileutils'
require 'json'
require 'net/http'
require 'set'
require 'stringio'
require 'time'
require 'timeout'
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
  # Bound parallel live fetches so one slow host cannot serialize the whole run.
  FEED_CONCURRENCY = 6
  # After this many consecutive failures, annotate as unhealthy (never permanent-drop).
  UNHEALTHY_FAILURE_THRESHOLD = 3

  BROWSER_UA = 'Mozilla/5.0 (compatible; ThreatActorInfo/1.0; +https://threatactor.info) ' \
               'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'

  # Native security/intel sources keep items that pass a light relevance gate.
  # General tech sources must match a stricter security-relevance pattern.
  # `alternate_urls` are tried in order after the primary `url` within the same
  # per-feed wall-clock deadline (403/empty responses advance to the next URL).
  RSS_FEEDS = [
    {
      name: 'BleepingComputer',
      url: 'https://www.bleepingcomputer.com/feed/',
      # Bot 403s persist across www/apex and category paths; keep trying alternates
      # each run. Google News site: RSS is intentionally omitted — it often wraps
      # google.com/url redirects rather than canonical bleepingcomputer.com links.
      alternate_urls: [
        'https://bleepingcomputer.com/feed/',
        'https://www.bleepingcomputer.com/feed/news/',
        'https://www.bleepingcomputer.com/feed/category/security/',
        'https://www.bleepingcomputer.com/news/feed/',
        'https://feeds.feedburner.com/BleepingComputer'
      ],
      weight: 2,
      category: :security
    },
    { name: 'The Hacker News', url: 'https://feeds.feedburner.com/TheHackersNews', weight: 2, category: :security },
    { name: 'KrebsOnSecurity', url: 'https://krebsonsecurity.com/feed/', weight: 2, category: :security },
    { name: 'DarkReading', url: 'https://www.darkreading.com/rss.xml', weight: 2, category: :security },
    # SecurityWeek has historically 403'd bot UAs; keep alternate endpoints + health tracking.
    {
      name: 'SecurityWeek',
      url: 'https://www.securityweek.com/feed/',
      alternate_urls: [
        'https://www.securityweek.com/feed',
        'https://feeds.feedburner.com/Securityweek',
        'https://securityweek.com/feed/'
      ],
      weight: 2,
      category: :security
    },
    { name: 'The Record', url: 'https://therecord.media/feed', weight: 2, category: :security },
    # CISA/Akamai has intermittently 403'd GHA runners (~80ms) since Nov 5, 2026 even
    # with browser UA + Accept headers. Keep trying documented alternate advisory /
    # news / legacy US-CERT feed paths within the same per-feed deadline.
    {
      name: 'CISA Advisories',
      url: 'https://www.cisa.gov/cybersecurity-advisories/all.xml',
      alternate_urls: [
        'https://www.cisa.gov/cybersecurity-advisories/cybersecurity-advisories.xml',
        'https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml',
        'https://www.cisa.gov/news.xml',
        'https://www.cisa.gov/uscert/ncas/alerts.xml',
        'https://cisa.gov/cybersecurity-advisories/all.xml'
      ],
      weight: 2,
      category: :security
    },
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
    # Product / common-noun / nationality / metaphor collisions from archive audit:
    defender payload falcon bluesky brazilian district sanctions apocalypse spring
    hermes cyclops eclipse nightmare aurora anonymous
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
    whatsapp signal dropbox box icloud office365 defender falcon bluesky
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

  def compact_keyword(keyword)
    normalize_keyword(keyword).delete(' ')
  end

  # Split CamelCase / PascalCase tokens into spaced words before lowercasing.
  # "ShinyHunters" -> "Shiny Hunters"; "APT28" stays "APT28".
  def camel_spaced_form(raw)
    raw.to_s.strip
       .gsub(/([a-z0-9])([A-Z])/, '\1 \2')
       .gsub(/([A-Z]+)([A-Z][a-z])/, '\1 \2')
  end

  # Forms used for primary-name co-occurrence checks (includes CamelCase↔spaced).
  def alias_keyword_forms(raw)
    raw_s = raw.to_s.strip
    return [] if raw_s.empty?

    forms = [normalize_keyword(raw_s), compact_keyword(raw_s)]
    spaced = camel_spaced_form(raw_s)
    forms << normalize_keyword(spaced) unless spaced.empty?
    forms.map { |form| normalize_keyword(form) }.uniq.reject(&:empty?)
  end

  # Index forms: keep explicit aliases + compact multi-word → single token
  # ("Shiny Hunters" → shinyhunters). Do NOT auto-index CamelCase→spaced
  # ("NewWave" → "new wave") — that creates English false positives.
  def indexable_alias_forms(raw)
    raw_s = raw.to_s.strip
    return [] if raw_s.empty?

    [normalize_keyword(raw_s), compact_keyword(raw_s)]
      .map { |form| normalize_keyword(form) }
      .uniq
      .reject(&:empty?)
  end

  # Title-case / ALL-CAPS tokens (news headlines), not lowercase English prose
  # or bare digits ("10" in "Windows 10").
  def prominent_name_token?(token)
    value = token.to_s
    return false if value.match?(/\A\d+\z/)

    value.match?(/\A(?:[A-Z][A-Za-z0-9'\-]*|[A-Z]{2,}[A-Z0-9'\-]*)\z/)
  end

  # True CamelCase/PascalCase compounds (ShinyHunters, GhostAction), not
  # single-capital tokens (Dataleak) or digit suffixes (Windows10).
  def camel_case_compound?(raw)
    raw.to_s.match?(/[a-z][A-Z]/)
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

  # Match primary actor names across compact/spaced camelCase variants.
  def primary_text_match?(haystack, primary)
    alias_keyword_forms(primary).any? { |form| text_match?(haystack, form) }
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

  # Actor-page Recent News titles: strip markup, escape only markdown-significant
  # brackets. Do not HTML-escape (avoids &#39; churn). /news/ still uses Liquid
  # | escape with http(s)-only links.
  def sanitize_news_markdown_text(text)
    sanitize_feed_text(text).gsub(']', '&#93;').gsub('[', '&#91;')
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

  # Map curated labels (e.g. Lazarus, Clop, Rhysida) onto canonical YAML actor names.
  def resolve_actor_record(name, actors)
    exact = actors.find { |actor| actor['name'].casecmp?(name) }
    return exact if exact

    hits = actors.select do |actor|
      Array(actor['aliases']).any? { |alias_name| alias_name.casecmp?(name) }
    end
    return nil if hits.empty?

    # Prefer longer canonical names (Lazarus Group over short collisions).
    hits.max_by { |actor| [actor['name'].length, actor['name']] }
  end

  def operation_style_actor?(actor_name)
    actor_name.to_s.match?(/\AOperation\b/i)
  end

  def alias_requires_own_primary?(alias_kw, actor_name, primary_names)
    return true if operation_style_actor?(actor_name)

    own = normalize_keyword(actor_name)
    own_compact = compact_keyword(actor_name)
    # Spaced/compact form of the owner name is not a cross-actor leak
    # (e.g. alias "shiny hunters" for primary ShinyHunters).
    return false if compact_keyword(alias_kw) == own_compact

    primary_names.any? do |other|
      next false if other == own
      next false if other.length < 5
      # Exact shared aliases (Star Blizzard on Callisto) are intentional cluster links.
      next false if alias_kw == other
      # Stoplisted English/common primaries (hunters, play, ...) are not distinctive
      # enough to force a primary-name co-occurrence gate on longer aliases.
      next false if ambiguous_alias?(other)

      # Proper containment: "handala hack" contains primary "handala".
      alias_kw.match?(/(?<![[:alnum:]])#{Regexp.escape(other)}(?![[:alnum:]])/)
    end
  end

  def build_keyword_index(actors = load_actor_records)
    # keyword -> [{name:, url:, alias:, context_required:, require_primary:}, ...]
    index = Hash.new { |h, k| h[k] = [] }
    primary_names = actors.map { |actor| normalize_keyword(actor['name']) }.to_set

    CURATED_KEYWORDS.each do |curated_name, words|
      resolved = resolve_actor_record(curated_name, actors)
      canonical_name = resolved ? resolved['name'] : curated_name
      url = resolved ? resolved['url'].to_s : ''
      words.each do |word|
        next unless usable_alias?(word, curated: true)

        indexable_alias_forms(word).each do |kw|
          next unless usable_alias?(kw, curated: true)

          index[kw] << {
            name: canonical_name,
            url: url,
            alias: kw,
            context_required: false,
            require_primary: operation_style_actor?(canonical_name)
          }
        end
      end
    end

    actors.each do |actor|
      candidates = [actor['name'], *actor['aliases']]
      candidates.each do |raw|
        next unless usable_alias?(raw, curated: false)

        # Evaluate require_primary on the original alias text so compacting
        # "Handala Hack" → handalahack cannot drop the Handala co-occurrence gate.
        requires_primary = alias_requires_own_primary?(
          normalize_keyword(raw), actor['name'], primary_names
        )
        # Only CamelCase compounds may match spaced Title-Case headlines via
        # adjacent-token join (ShinyHunters ↔ "Shiny Hunters").
        spaced_title_match = camel_case_compound?(raw) && !raw.to_s.include?(' ')

        indexable_alias_forms(raw).each do |kw|
          next unless usable_alias?(kw, curated: false)

          index[kw] << {
            name: actor['name'],
            url: actor['url'],
            alias: kw,
            context_required: context_required_alias?(kw, curated: false) || product_vendor_alias?(kw),
            require_primary: requires_primary,
            spaced_title_match: spaced_title_match
          }
        end
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

    # Token candidates must preserve the old word-boundary semantics:
    # "APT28-Linked" and "LockBit's" still expose apt28 / lockbit, while
    # hyphenated aliases like "storm-0940" remain lookup keys too.
    tokens = text.downcase.scan(/[a-z0-9]+(?:[.'\-][a-z0-9]+)*/)
    tokens.concat(text.downcase.scan(/[a-z0-9]+/))
    tokens.uniq!
    accept = lambda do |entry, alias_key|
      if entry[:context_required] || entry['context_required']
        return false unless actor_context_match?(text, alias_key)
      end
      if entry[:require_primary] || entry['require_primary']
        primary = entry[:name] || entry['name']
        return false unless primary_text_match?(text, primary)
      end
      true
    end

    tokens.each do |tok|
      Array(single[tok]).each do |entry|
        alias_key = entry[:alias] || entry['alias'] || tok
        # Re-check boundaries so "apt28" inside a longer alnum run cannot hit.
        next unless text_match?(text, alias_key)
        next unless accept.call(entry, alias_key)

        key = entry[:name] || entry['name']
        matched[key] ||= entry
      end
    end

    # Compact CamelCase aliases (ShinyHunters) may appear spaced in headlines
    # ("Shiny Hunters"). Join adjacent Title-Case / ALL-CAPS tokens and look up
    # the compact form — never match lowercase English prose like "new wave".
    surface_tokens = text.scan(/[A-Za-z0-9]+(?:[.'\-][A-Za-z0-9]+)*/)
    (0...surface_tokens.length).each do |start|
      (2..3).each do |width|
        break if start + width > surface_tokens.length

        slice = surface_tokens[start, width]
        next unless slice.all? { |tok| prominent_name_token?(tok) }

        compact = slice.map { |tok| tok.downcase.gsub(/[^a-z0-9]/, '') }.join
        next if compact.length < 6

        Array(single[compact]).each do |entry|
          next unless entry[:spaced_title_match] || entry['spaced_title_match']

          alias_key = entry[:alias] || entry['alias'] || compact
          next unless accept.call(entry, alias_key)

          key = entry[:name] || entry['name']
          matched[key] ||= entry
        end
      end
    end

    multi.each do |keyword, pattern, entries|
      next unless pattern.match?(text)

      entries.each do |entry|
        next unless accept.call(entry, keyword)

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

  # Legacy helper retained for tests; permanent auto-drop is no longer used.
  def drop_feed_on_forbidden?(health_entry)
    return false unless health_entry.is_a?(Hash)

    error = health_entry['error'].to_s
    error.match?(/\b403\b/) || error.downcase.include?('forbidden')
  end

  def feed_urls(feed)
    urls = [feed[:url], *Array(feed[:alternate_urls])]
    urls.map { |url| url.to_s.strip }.reject(&:empty?).uniq
  end

  # Try primary then alternate URLs within one wall-clock deadline. Per-URL
  # open/read timeouts (Timeout::Error subclasses) advance to the next URL when
  # budget remains; only an exhausted deadline is terminal.
  def with_feed_url_fallbacks(urls, deadline_seconds: FEED_DEADLINE_SECONDS)
    deadline_at = Time.now + deadline_seconds.to_f
    last_error = nil

    Array(urls).each do |url|
      remaining = deadline_at - Time.now
      if remaining <= 0.05
        raise Timeout::Error, "deadline exceeded (#{deadline_seconds.round}s)"
      end

      begin
        return [url, yield(url, remaining)]
      rescue Timeout::Error => e
        remaining_after = deadline_at - Time.now
        deadline_hit = e.message.to_s.match?(/deadline exceeded/i) || remaining_after <= 0.05
        if deadline_hit
          raise Timeout::Error, "deadline exceeded (#{deadline_seconds.round}s)"
        end

        last_error = e
        next
      rescue StandardError => e
        last_error = e
        next
      end
    end

    raise(last_error || StandardError.new('all feed URLs failed'))
  end

  # Browser-like headers. Optional `url` sets Referer to the feed origin — Akamai
  # bot scoring often treats bare Net::HTTP requests without Referer/Sec-Fetch-* as
  # automated. Callers may still pass an explicit headers hash to override.
  def browser_http_headers(url: nil)
    headers = {
      'User-Agent' => BROWSER_UA,
      'Accept' => 'application/rss+xml, application/atom+xml, application/xml, text/xml;q=0.9, */*;q=0.8',
      'Accept-Language' => 'en-US,en;q=0.9',
      # Prefer gzip so large advisory feeds (e.g. CISA) transfer faster when offered.
      'Accept-Encoding' => 'gzip, deflate',
      'Cache-Control' => 'no-cache',
      'Pragma' => 'no-cache',
      'Connection' => 'close',
      'Upgrade-Insecure-Requests' => '1',
      'Sec-Fetch-Dest' => 'document',
      'Sec-Fetch-Mode' => 'navigate',
      'Sec-Fetch-Site' => 'none',
      'Sec-Fetch-User' => '?1'
    }
    referer = origin_referer(url)
    headers['Referer'] = referer if referer
    headers
  end

  def origin_referer(url)
    uri = URI.parse(url.to_s)
    return nil unless uri.is_a?(URI::HTTP)
    return nil if uri.host.to_s.strip.empty?

    "#{uri.scheme}://#{uri.host}/"
  rescue URI::InvalidURIError, ArgumentError
    nil
  end

  # True when the body looks like RSS/Atom rather than an HTML challenge / empty
  # soft-block page. Used so URL fallbacks advance on Akamai "Access Denied" HTML.
  def feed_body_usable?(raw)
    text = raw.to_s.lstrip
    return false if text.empty?
    return false if text.match?(/\A(?:<!DOCTYPE\s+html|<html[\s>])/i)

    text.match?(/<(?:rss|feed|rdf:RDF)[\s>]/i) ||
      text.match?(/<(?:item|entry)[\s>]/i)
  end

  # Hard wall-clock deadline for an arbitrary block (fetch, parse, or both).
  # MRI's Timeout.timeout alone is unreliable around blocked SSL reads / long
  # CPU-bound XML parses; combine an interruptible worker thread with join.
  def run_with_deadline(deadline)
    deadline = deadline.to_f
    raise ArgumentError, 'deadline must be positive' unless deadline.positive?

    result = nil
    error = nil
    worker = Thread.new do
      begin
        result = yield
      rescue Exception => e # rubocop:disable Lint/RescueException -- must surface to join
        error = e
      end
    end

    finished = worker.join(deadline)
    unless finished
      force_kill_thread(worker)
      raise Timeout::Error, "deadline exceeded (#{deadline.round}s)"
    end
    raise error if error

    result
  end

  # Hard wall-clock deadline covering DNS/connect/TLS/read/redirects.
  def fetch_url_with_deadline(url, deadline: FEED_DEADLINE_SECONDS, headers: nil,
                              open_timeout: OPEN_TIMEOUT, read_timeout: READ_TIMEOUT, fetcher: nil)
    headers ||= browser_http_headers(url: url)
    run_with_deadline(deadline) do
      if fetcher
        fetcher.call(url, headers: headers, open_timeout: open_timeout, read_timeout: read_timeout)
      else
        http_get_with_timeouts(url, headers: headers, open_timeout: open_timeout, read_timeout: read_timeout)
      end
    end
  end

  # Trim RSS/Atom XML to the first max_items entries before a full DOM parse.
  # Huge advisory feeds (CISA) otherwise spend minutes inside RSS::Parser.parse
  # *after* the HTTP fetch already finished — outside any prior deadline.
  def trim_feed_xml(raw, max_items: MAX_PER_FEED)
    text = raw.to_s
    return text if text.empty? || max_items.to_i <= 0

    item_tag = nil
    if text.match?(/<item[\s>]/i)
      item_tag = 'item'
    elsif text.match?(/<entry[\s>]/i)
      item_tag = 'entry'
    else
      return text
    end

    close_re = %r{</#{item_tag}\s*>}i
    count = 0
    last_end = nil
    text.to_enum(:scan, close_re).each do
      count += 1
      last_end = Regexp.last_match.end(0)
      break if count >= max_items
    end
    return text if last_end.nil? || count < max_items

    # Keep the document head through the Nth item, then close the root element.
    head = text[0...last_end]
    if item_tag == 'item'
      "#{head}\n</channel>\n</rss>\n"
    else
      "#{head}\n</feed>\n"
    end
  end

  def http_get_with_timeouts(url, headers:, open_timeout:, read_timeout:, limit: 5)
    raise ArgumentError, 'too many redirects' if limit <= 0

    uri = URI.parse(url.to_s)
    raise ArgumentError, "unsupported URL: #{url}" unless uri.is_a?(URI::HTTP)

    request_headers = headers.is_a?(Hash) ? headers.dup : {}
    unless request_headers.key?('Referer') || request_headers.key?('referer')
      referer = origin_referer(url)
      request_headers['Referer'] = referer if referer
    end

    http = Net::HTTP.new(uri.host, uri.port)
    begin
      http.use_ssl = uri.scheme == 'https'
      http.open_timeout = open_timeout
      http.read_timeout = read_timeout
      http.write_timeout = read_timeout if http.respond_to?(:write_timeout=)
      http.max_retries = 0 if http.respond_to?(:max_retries=)

      path = uri.request_uri
      request = Net::HTTP::Get.new(path)
      request_headers.each { |key, value| request[key] = value }

      response = http.request(request)
      case response
      when Net::HTTPSuccess
        body = response.body.to_s
        encoding = response['Content-Encoding'].to_s.downcase
        if encoding.include?('gzip')
          require 'zlib'
          body = Zlib::GzipReader.new(StringIO.new(body)).read
        elsif encoding.include?('deflate')
          require 'zlib'
          body = begin
            Zlib::Inflate.new.inflate(body)
          rescue Zlib::DataError
            Zlib::Inflate.new(-Zlib::MAX_WINDOW_BITS).inflate(body)
          end
        end
        body
      when Net::HTTPRedirection
        location = response['location'].to_s
        raise ArgumentError, 'redirect without location' if location.empty?

        next_url = URI.join(uri.to_s, location).to_s
        http_get_with_timeouts(
          next_url,
          headers: request_headers,
          open_timeout: open_timeout,
          read_timeout: read_timeout,
          limit: limit - 1
        )
      else
        raise "HTTP #{response.code} #{response.message}".strip
      end
    ensure
      http.finish if http.started?
    end
  end

  def force_kill_thread(thread)
    return unless thread&.alive?

    thread.kill
    thread.join(1)
  rescue StandardError
    nil
  end

  def map_concurrent(items, concurrency: FEED_CONCURRENCY)
    list = Array(items)
    return [] if list.empty?

    workers = [[concurrency.to_i, 1].max, list.size].min
    queue = Queue.new
    list.each_with_index { |item, index| queue << [index, item] }
    results = Array.new(list.size)
    errors = []
    mutex = Mutex.new

    threads = Array.new(workers) do
      Thread.new do
        loop do
          index, item = queue.pop(true)
          begin
            results[index] = yield(item)
          rescue StandardError => e
            mutex.synchronize { errors << e }
          end
        rescue ThreadError
          break
        end
      end
    end
    threads.each(&:join)
    raise errors.first if errors.any?

    results
  end

  # Never permanently skip a source. Track consecutive failures and mark
  # unhealthy after UNHEALTHY_FAILURE_THRESHOLD failures; always retry next run.
  def merge_source_health_entry(current_entry, previous_entry = nil, now: Time.now.utc)
    current = current_entry.is_a?(Hash) ? current_entry.transform_keys(&:to_s) : {}
    previous = previous_entry.is_a?(Hash) ? previous_entry.transform_keys(&:to_s) : {}
    entry = current.dup
    entry.delete('dropped')

    timed_out = entry['error'].to_s.match?(/deadline exceeded|timed?\s*out/i) || entry['timed_out'] == true
    entry['timed_out'] = timed_out if timed_out || entry.key?('timed_out')

    if entry['ok']
      entry['consecutive_failures'] = 0
      entry['last_success_at'] = (parse_time(entry['last_success_at']) || now).utc.iso8601
      entry['unhealthy'] = false
    else
      failures = previous['consecutive_failures'].to_i + 1
      entry['consecutive_failures'] = failures
      if previous['last_success_at']
        entry['last_success_at'] = previous['last_success_at']
      end
      entry['unhealthy'] = failures >= UNHEALTHY_FAILURE_THRESHOLD
    end
    entry
  end

  def normalize_source_health(health)
    Hash(health).each_with_object({}) do |(name, entry), out|
      next unless entry.is_a?(Hash)

      cleaned = entry.transform_keys(&:to_s).dup
      was_dropped = cleaned.delete('dropped')
      failures = cleaned['consecutive_failures'].to_i
      # Migrating legacy permanent-drop flags: treat them as having already
      # crossed the unhealthy threshold so the next run still alerts, while
      # always retrying the source.
      if was_dropped && failures < UNHEALTHY_FAILURE_THRESHOLD
        failures = UNHEALTHY_FAILURE_THRESHOLD
      end
      cleaned['consecutive_failures'] = failures
      cleaned['unhealthy'] = failures >= UNHEALTHY_FAILURE_THRESHOLD
      out[name.to_s] = cleaned
    end
  end

  def unhealthy_sources(source_health)
    Hash(source_health).select do |_name, entry|
      entry.is_a?(Hash) && (entry['unhealthy'] || entry[:unhealthy])
    end
  end
end
