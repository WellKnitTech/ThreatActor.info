# frozen_string_literal: true

# Neutralize Liquid delimiters in imported / generated prose so Jekyll
# (`jekyll build --safe`) never treats ETDA-style cross-refs or stray braces
# as Liquid tags.
#
# ETDA/ThaiCERT (and some MISP-derived text) embeds cross-references like:
#   {{TA505, Graceful Spider, Gold Evergreen}}
#   {{Hacking Team}}
#   {{Subgroup: [Unnamed group USA]}}
# When those land in collection markdown bodies, Liquid tries to evaluate them
# and can raise Liquid::SyntaxError (especially on unclosed `{{`).
module LiquidSafeText
  module_function

  LIQUID_DELIMITER_PATTERN = /(\{\{|\{%)/.freeze

  # Well-formed `{{ ... }}` blocks (non-greedy, single-line / short spans).
  ETDA_CROSS_REF_PATTERN = /\{\{\s*([^{}]+?)\s*\}\}/.freeze

  # Well-formed `{% ... %}` blocks (rare in intel prose; neutralize content).
  LIQUID_TAG_PATTERN = /\{%\s*([^{%]*?)\s*%\}/.freeze

  def contains_liquid_delimiters?(text)
    text.to_s.match?(LIQUID_DELIMITER_PATTERN)
  end

  # Convert ETDA-style cross-refs to plain text and neutralize leftover delimiters.
  #
  # `{{Name}}`            -> `Name`
  # `{{Name, Alias, ...}}` -> `Name (Alias, ...)`
  # `{{citation:1}}` / `{{1}}` -> `[#1]` (preserve generate-pages footnote placeholders)
  # Unclosed / stray `{{` / `{%` -> removed (content kept when possible)
  def sanitize(text)
    return '' if text.nil?

    out = text.to_s.dup
    out = convert_citation_placeholders(out)
    out = unwrap_etda_cross_refs(out)
    out = unwrap_liquid_tags(out)
    neutralize_stray_delimiters(out)
  end

  def convert_citation_placeholders(text)
    text.gsub(/\{\{(?:citation:)?(\d+)\}\}/, '[#\1]')
  end

  def unwrap_etda_cross_refs(text)
    text.gsub(ETDA_CROSS_REF_PATTERN) do
      format_cross_ref(Regexp.last_match(1))
    end
  end

  def unwrap_liquid_tags(text)
    text.gsub(LIQUID_TAG_PATTERN) do
      inner = Regexp.last_match(1).to_s.strip
      inner.empty? ? '' : inner
    end
  end

  def format_cross_ref(inner)
    parts = inner.to_s.split(/\s*,\s*/).map(&:strip).reject(&:empty?)
    return inner.to_s.strip if parts.empty?
    return parts.first if parts.length == 1

    "#{parts.first} (#{parts[1..].join(', ')})"
  end

  def neutralize_stray_delimiters(text)
    text
      .gsub('{{', '')
      .gsub('}}', '')
      .gsub('{%', '')
      .gsub('%}', '')
  end
end
