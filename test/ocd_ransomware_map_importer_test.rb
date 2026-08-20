# frozen_string_literal: true

require 'digest'
require 'fileutils'
require 'json'
require 'minitest/autorun'
require 'tmpdir'
require 'yaml'
require_relative '../scripts/import-ocd-ransomware-map'

class OcdRansomwareMapImporterTest < Minitest::Test
  FIXTURE_ROOT = File.expand_path('fixtures/ocd-ransomware-map', __dir__)

  def test_plan_extracts_deterministic_text_and_only_emits_review_candidates
    Dir.mktmpdir do |output|
      importer = OcdRansomwareMapImporter.new(snapshot: fixture('current'), output: output,
                                                expected_pdf_sha256: fixture_pdf_sha256, expected_readme_sha256: fixture_readme_sha256)

      report = importer.plan

      assert_equal 'accepted', report.fetch('status')
      assert_equal 2, report.fetch('candidates').length
      assert report.fetch('candidates').all? { |candidate| candidate['needs_review'] }
      assert_equal 'New addition', report.fetch('candidates').find { |candidate| candidate['event_type'] == 'New addition' }.fetch('event_type')
      assert_equal 'source_changelog', report.fetch('candidates').first.fetch('evidence_type')
      assert report.fetch('extraction').fetch('text_sha256')
      refute File.exist?(File.join(output, 'extracted.txt'))
      refute File.exist?(File.join(output, 'source.pdf'))
    end
  end

  def test_plan_rejects_output_path_traversal
    Dir.mktmpdir do |root|
      outside = File.join(root, '..', 'escaped-ocd-output')
      importer = OcdRansomwareMapImporter.new(snapshot: fixture('current'), output: outside,
                                                expected_pdf_sha256: fixture_pdf_sha256, expected_readme_sha256: fixture_readme_sha256)
      assert_raises(ArgumentError) { importer.plan }
    end
  end

  def test_changed_pdf_fails_closed_without_emitting_candidates
    Dir.mktmpdir do |snapshot|
      FileUtils.cp_r(File.join(fixture('changed'), '.'), snapshot)
      importer = OcdRansomwareMapImporter.new(snapshot: snapshot, output: File.join(snapshot, 'report'),
                                                expected_pdf_sha256: fixture_pdf_sha256, expected_readme_sha256: fixture_readme_sha256)

      report = importer.plan

      assert_equal 'quarantined', report.fetch('status')
      assert_equal 'pdf_checksum_mismatch', report.fetch('diagnostics').first.fetch('code')
      assert_empty report.fetch('candidates')
    end
  end

  def test_malformed_pdf_fails_closed_when_pdf_text_extraction_changes
    importer = OcdRansomwareMapImporter.new(snapshot: fixture('malformed'), output: Dir.mktmpdir,
                                              expected_pdf_sha256: malformed_pdf_sha256, expected_readme_sha256: fixture_readme_sha256)

    report = importer.plan

    assert_equal 'quarantined', report.fetch('status')
    assert_equal 'pdf_structure_invalid', report.fetch('diagnostics').first.fetch('code')
    assert_empty report.fetch('candidates')
  end

  def test_missing_pdftotext_reports_installable_prerequisite
    importer = OcdRansomwareMapImporter.new(snapshot: fixture('current'), output: Dir.mktmpdir,
                                              expected_pdf_sha256: fixture_pdf_sha256, expected_readme_sha256: fixture_readme_sha256,
                                              pdftotext_bin: '/definitely/missing/pdftotext')

    report = importer.plan

    assert_equal 'quarantined', report.fetch('status')
    assert_equal 'missing_pdf_text_extractor', report.fetch('diagnostics').first.fetch('code')
    assert_includes report.fetch('diagnostics').first.fetch('message'), 'poppler-utils'
  end

  private

  def fixture(name)
    File.join(FIXTURE_ROOT, name)
  end

  def fixture_pdf_sha256
    Digest::SHA256.file(File.join(fixture('current'), 'source.pdf')).hexdigest
  end

  def malformed_pdf_sha256
    Digest::SHA256.file(File.join(fixture('malformed'), 'source.pdf')).hexdigest
  end

  def fixture_readme_sha256
    Digest::SHA256.file(File.join(fixture('current'), 'README.md')).hexdigest
  end
end