# frozen_string_literal: true

source 'https://rubygems.org'

git_source(:github) { |repo_name| "https://github.com/#{repo_name}" }

# Specify your gem's dependencies in tls-checker.gemspec
gemspec

# rubocop:disable Security/Eval
#
# Gemfile.local is ignored in .gitignore.  When hacking this gem, it might be
# useful to use a pre-release version of some dependency, in this case add them
# to Gemfile.local:
#
# ------------------------------------- 8< -------------------------------------
# gem 'internet_security_event', path: '../internet_security_event'
# ------------------------------------- 8< -------------------------------------
eval(File.read('Gemfile.local'), binding) if File.exist? 'Gemfile.local'
# rubocop:enable Security/Eval
