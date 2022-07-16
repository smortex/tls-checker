# frozen_string_literal: true

require 'bundler/gem_tasks'
require 'github_changelog_generator/task'
require 'rspec/core/rake_task'

RSpec::Core::RakeTask.new(:spec)

GitHubChangelogGenerator::RakeTask.new :changelog do |config|
  config.header = <<~HEADER.chomp
    # Changelog

    All notable changes to this project will be documented in this file.

    The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
    and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
  HEADER
  config.exclude_labels = %w[duplicate question invalid wontfix wont-fix skip-changelog ignore]
  config.user = 'smortex'
  config.project = 'tls-checker'
  config.since_tag = 'v1.4.0'
  config.issues = false
  require 'tls_checker/version'
  config.future_release = "v#{TLSChecker::VERSION}"
end

task default: :spec
