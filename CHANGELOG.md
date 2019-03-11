# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- New metadata in generated events: af (address fanily, one of 'inet' and
  'inet6'), hostname, address and port.

### Changed

- Ensure events' ttl is an Integer.

## [1.3.0]

### Changed

- Revert to the pre-1.2.0 behavior when a remote service is not reachable and
  emit a critical event.

## [1.2.0]

### Changed

- Skip completely TLSA check if a connexion certificate cannot be fetched;
- Do not generate an event when a connexion to a remote service is not
  possible.

## [1.1.1]

### Changed

- Handle Errno::EHOSTUNREACH exceptions gracefully when attempting to fetch a
  certificate.

## [1.1.0]

### Added

- Make it possible to test services using an IP address;
- Report validity of certificates when a TLSA record is found in the DNS.

[Unreleased]: https://github.com/smortex/tls-checker/compare/v1.3.0...HEAD
[1.3.0]: https://github.com/smortex/tls-checker/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/smortex/tls-checker/compare/v1.1.1...v1.2.0
[1.1.1]: https://github.com/smortex/tls-checker/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/smortex/tls-checker/compare/v1.0.0...v1.1.0
