# frozen_string_literal: true

source 'https://rubygems.org'

git_source(:github) {|repo_name| "https://github.com/#{repo_name}" }

# Specify your gem's dependencies in tls-checker.gemspec
gemspec

if File.exists? "#{__FILE__}.local"
  eval(File.read("#{__FILE__}.local"), binding)
end
