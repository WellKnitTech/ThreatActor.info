require 'fileutils'
require 'minitest/autorun'
require 'tmpdir'
require_relative '../scripts/generate-indexes'

class OcdEcosystemDigestTest < Minitest::Test
  FIXTURE = File.expand_path('fixtures/ocd-ransomware-map/accepted.yml', __dir__).freeze

  def test_only_accepted_records_with_citations_are_published_and_sharded
    Dir.mktmpdir do |dir|
      input = File.join(dir, 'data/imports/ocd-ransomware-map/accepted.yml')
      FileUtils.mkdir_p(File.dirname(input))
      FileUtils.cp(FIXTURE, input)
      Dir.chdir(dir) do
        generator = ThreatActorIndexGenerator.allocate
        payload = generator.send(:build_ocd_ecosystem, [{ url: '/lockbit', name: 'LockBit', aliases: [] }])
        assert_equal '1.0', payload[:schema_version]
        assert_equal 1, payload[:ecosystem_links].length
        assert_equal 1, payload[:ecosystem_events].length
        assert_equal 1, payload[:actors]['lockbit'][:relationships].length
        assert_equal 1, payload[:actors]['lockbit'][:events].length
        refute payload[:ecosystem_links].any? { |record| record[:review_status] != 'accepted' }
        assert_equal 'Orange Cyberdefense CERT - World Watch', payload[:provenance][:ocd_ransomware_map][:publisher]
      end
    end
  end

  def test_empty_input_is_a_clean_empty_digest
    Dir.mktmpdir do |dir|
      Dir.chdir(dir) do
        generator = ThreatActorIndexGenerator.allocate
        payload = generator.send(:build_ocd_ecosystem, [{ url: '/lockbit', name: 'LockBit', aliases: [] }])
        assert_empty payload[:actors]
        assert_empty payload[:ecosystem_links]
        assert_empty payload[:ecosystem_events]
      end
    end
  end

  def test_generation_removes_obsolete_actor_shards
    Dir.mktmpdir do |dir|
      Dir.chdir(dir) do
        shard_dir = File.join('api', 'ransomware-ecosystem')
        FileUtils.mkdir_p(shard_dir)
        stale = File.join(shard_dir, 'retracted-actor.json')
        File.write(stale, '{}')

        generator = ThreatActorIndexGenerator.allocate
        generator.send(:remove_obsolete_ocd_actor_shards)
        generator.send(:write_ocd_actor_shards, {
                         schema_version: '1.0',
                         provenance: {},
                         source_disclaimer: 'test',
                         actors: {
                           'current-actor' => { relationships: [], events: [], mentions: [] }
                         }
                       })

        refute File.exist?(stale)
        assert File.exist?(File.join(shard_dir, 'current-actor.json'))
      end
    end
  end

  def test_publish_gate_rejects_visual_evidence_high_confidence_and_unsafe_citations
    generator = ThreatActorIndexGenerator.allocate
    base = {
      'review_status' => 'accepted',
      'src_ref' => { 'canonical_id' => 'actor:lockbit' },
      'dst_ref' => { 'canonical_id' => 'actor:nitro-spider' },
      'evidence' => {
        'evidence_kind' => 'plate_text',
        'evidence_quote' => 'LockBit and Nitro Spider appear together in the pinned map.',
        'source_snapshot_ref' => 'ocd:snapshot:v29:test',
        'citation_url' => 'https://github.com/cert-orangecyberdefense/ransomware_map/blob/main/map.pdf'
      }
    }
    refute generator.send(:normalize_ocd_record, base.merge('uncertainty_label' => 'layout_inferred'))
    refute generator.send(:normalize_ocd_record, base.merge('confidence' => 'high'))
    refute generator.send(:normalize_ocd_record, base.merge('evidence' => base['evidence'].merge('citation_url' => 'javascript:alert(1)')))
    refute generator.send(:normalize_ocd_record, base.merge('evidence' => base['evidence'].merge('evidence_quote' => 'x' * 501)))

    reviewed_high = base.merge(
      'confidence' => 'high',
      'uncertainty_label' => 'analyst_confirmed',
      'review' => { 'reviewed_by' => 'analyst', 'reviewed_at' => '2026-08-19T17:00:00Z', 'decision_note' => 'Confirmed against the pinned snapshot.' }
    )
    assert generator.send(:normalize_ocd_record, reviewed_high)
  end

  def test_publish_gate_allowlists_snapshot_and_exact_actor_ids
    Dir.mktmpdir do |dir|
      input = File.join(dir, 'data/imports/ocd-ransomware-map/accepted.yml')
      FileUtils.mkdir_p(File.dirname(input))
      File.write(input, <<~YAML)
        source_snapshot:
          map_version: 29
          git_commit: commit
          sha256: hash
          retrieved_at: 2026-08-19T17:00:00Z
          artifact_url: https://github.com/cert-orangecyberdefense/ransomware_map/blob/main/map.pdf
          license_note: mit
          evil: injected
        records:
          - relationship_id: ocd:rel:test
            review_status: accepted
            src_ref:
              canonical_id: actor:lockbit
            dst_ref:
              canonical_id: actor:unknown
            evidence:
              evidence_kind: plate_text
              evidence_quote: LockBit is listed in the pinned map.
              citation_url: https://github.com/cert-orangecyberdefense/ransomware_map/blob/main/map.pdf
              source_snapshot_ref: ocd:snapshot:v29:test
      YAML
      Dir.chdir(dir) do
        generator = ThreatActorIndexGenerator.allocate
        payload = generator.send(:build_ocd_ecosystem, [{ url: '/lockbit', name: 'LockBit', aliases: ['ABCD'] }])
        snapshot = payload[:provenance][:ocd_ransomware_map]
        assert_equal 'all_rights_reserved', snapshot[:license_note]
        refute snapshot.key?(:evil)
        assert_equal 1, payload[:actors].length
        assert_equal 1, payload[:actors]['lockbit'][:relationships].length
        refute payload[:actors].key?('abcd-other')
      end
    end
  end
end
