# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- Handle Errno::EHOSTUNREACH exceptions gracefully when attempting to fetch a
  certificate.

## [1.1.0]

### Added

- Make it possible to test services using an IP address;
- Report validity of certificates when a TLSA record is found in the DNS.

[Unreleased]: https://github.com/smortex/tls-checker/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/smortex/tls-checker/compare/v1.0.0...v1.1.0
