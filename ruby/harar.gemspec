# frozen_string_literal: true

require_relative "lib/harar/version"

Gem::Specification.new do |s|
  s.name = "harar"
  s.version = Harar::VERSION
  s.summary = "harar's client: Harar.vault. Where each secret may go, and the secret itself for one host only."
  s.license = "MIT"
  s.authors = ["Sami Fouad"]
  s.homepage = "https://harar.addis.gg"
  s.metadata = {
    "source_code_uri" => "https://github.com/addiscorp/harar",
    "rubygems_mfa_required" => "true"
  }
  s.required_ruby_version = ">= 3.0"
  s.files = ["lib/harar.rb", "lib/harar/version.rb", "README.md", "LICENSE"]
end
