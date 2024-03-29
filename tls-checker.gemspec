# frozen_string_literal: true

lib = File.expand_path('lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'tls_checker/version'

Gem::Specification.new do |spec|
  spec.name          = 'tls-checker'
  spec.version       = TLSChecker::VERSION
  spec.authors       = ['Romain Tartière']
  spec.email         = ['romain@blogreen.org']

  spec.summary       = 'Report expired/about to expires certificates used in TLS connexions'
  spec.homepage      = 'https://github.com/smortex/tls-checker'
  spec.license       = 'MIT'
  spec.required_ruby_version = Gem::Requirement.new('>= 2.6.0')

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files = Dir.chdir(File.expand_path(__dir__)) do
    `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  end
  spec.bindir        = 'exe'
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ['lib']

  spec.add_dependency 'internet_security_event', '>= 2', '< 4'

  spec.add_development_dependency 'bundler'
  spec.add_development_dependency 'github_changelog_generator'
  spec.add_development_dependency 'midi-smtp-server'
  spec.add_development_dependency 'rake'
  spec.add_development_dependency 'rspec'
  spec.add_development_dependency 'rubocop'
  spec.add_development_dependency 'rubocop-rake'
  spec.add_development_dependency 'rubocop-rspec'
  spec.add_development_dependency 'simplecov'
end
