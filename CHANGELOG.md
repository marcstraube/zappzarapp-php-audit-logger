# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0](https://github.com/marcstraube/zappzarapp-php-audit-logger/compare/v1.0.0...v1.1.0) (2026-04-16)


### Features

* add file size limits to FileLogReader and FileLogWriter ([#3](https://github.com/marcstraube/zappzarapp-php-audit-logger/issues/3), [#6](https://github.com/marcstraube/zappzarapp-php-audit-logger/issues/6)) ([#29](https://github.com/marcstraube/zappzarapp-php-audit-logger/issues/29)) ([3639afd](https://github.com/marcstraube/zappzarapp-php-audit-logger/commit/3639afd56c853ee17c63298f8070bd2966ecfa0e))
* add schema type validation for id and user_id fields ([#7](https://github.com/marcstraube/zappzarapp-php-audit-logger/issues/7)) ([#30](https://github.com/marcstraube/zappzarapp-php-audit-logger/issues/30)) ([d32e1a2](https://github.com/marcstraube/zappzarapp-php-audit-logger/commit/d32e1a2cc1d58ccf5bb3e973c0dc8edd0cb183fe))


### Bug Fixes

* add PHPStan ignore for PHP 8.5 protected(set) asymmetric visibility ([#36](https://github.com/marcstraube/zappzarapp-php-audit-logger/issues/36)) ([c5118ed](https://github.com/marcstraube/zappzarapp-php-audit-logger/commit/c5118eddcf5df3e45a9151becc7b2219d1e90a72))
* internal improvements (6 issues) ([#25](https://github.com/marcstraube/zappzarapp-php-audit-logger/issues/25)) ([237e882](https://github.com/marcstraube/zappzarapp-php-audit-logger/commit/237e88279aa5a25368af3632388b55407085c182))


### Code Refactoring

* extract ChecksumCalculator and FileLogWriter from AuditLogger ([#8](https://github.com/marcstraube/zappzarapp-php-audit-logger/issues/8)) ([#28](https://github.com/marcstraube/zappzarapp-php-audit-logger/issues/28)) ([b75c7f8](https://github.com/marcstraube/zappzarapp-php-audit-logger/commit/b75c7f8898e42455fab51d8cd4a3adac11ba7258))
* extract shared result-mapping logic into ResultMapper ([#9](https://github.com/marcstraube/zappzarapp-php-audit-logger/issues/9)) ([#27](https://github.com/marcstraube/zappzarapp-php-audit-logger/issues/27)) ([81e0396](https://github.com/marcstraube/zappzarapp-php-audit-logger/commit/81e039625bef4e74f0d04411bc191e3ad677085b))
* Node.js parity for verify() and logAdmin() ([#31](https://github.com/marcstraube/zappzarapp-php-audit-logger/issues/31)) ([6492ca5](https://github.com/marcstraube/zappzarapp-php-audit-logger/commit/6492ca5cc6ff7e73b043ab839f2a946939020df9))


### Documentation

* document DB query timeout configuration ([#11](https://github.com/marcstraube/zappzarapp-php-audit-logger/issues/11)) ([#32](https://github.com/marcstraube/zappzarapp-php-audit-logger/issues/32)) ([f1d2827](https://github.com/marcstraube/zappzarapp-php-audit-logger/commit/f1d28277058af7bbc5181de23e0015bc73e07566))

## [1.0.0] - 2026-02-15

### Added

#### Core API

- `AuditLoggerInterface` with `log()`, `logAuth()`, `logAdmin()`, `getLogsForEntity()`, `getLogsForUser()`, `verify()`, `readFileLog()`
- `AuditLogger` implementation with PDO, injectable encryption, configurable table name, optional file logging
- `NullAuditLogger` no-op implementation (Null Object pattern)
- `AuditLogEntry` immutable input DTO with field validation (max lengths, non-empty checks)
- `AuditLogResult` immutable output DTO with `dataError` field for corrupted data reporting

#### Encryption

- `EncryptionInterface` with two strategies:
  - `AppEncryption` — AES-256-GCM via OpenSSL with random 12-byte IV per operation (default)
  - `DatabaseEncryption` — Marker for SQL-level `encrypt_text()`/`decrypt_text()` functions
- HKDF-SHA256 key derivation with isolated keys for DB encryption, HMAC, and file encryption
- Minimum key length enforcement (32 bytes)

#### Integrity & Tamper Detection

- HMAC-SHA256 checksums over all audit-relevant fields (timestamp, userId, ipAddress, action, entityType, entityId, dataJson)
- Timing-safe verification via `hash_equals()`
- Null-byte field separators to prevent delimiter confusion attacks

#### File Fallback & Recovery

- Encrypted file-based fallback logging on database failure
- `FileLogReader` for programmatic file log recovery with line-level error reporting
- File permissions 0600 on creation
- Combined exception with both error messages when DB and file fallback fail

#### Database Support

- Migration SQL for PostgreSQL and MariaDB with immutability triggers (append-only)
- Composite indexes for entity, user, action, and timestamp queries
- Configurable table name with SQL injection prevention (regex-validated identifiers)
- Configurable query limit with optional upper bound (`maxLimit`)

#### GDPR Compliance

- `getLogsForUser()` for Subject Access Requests (Art. 15)
- Audit trail for deletion actions (Art. 17)
- Encryption at rest for all sensitive data (Art. 32)
- Entity-level access history for breach assessment (Art. 33)
- Documentation: `docs/gdpr-compliance.md`, `docs/database-encryption.md`

### Security

- AES-256-GCM with GCM auth tag prevents ciphertext tampering
- HKDF-derived keys — master key never used directly
- No PII in error messages or exception traces
- Prepared statements for all database queries
- Data size limit (10,000 bytes) prevents oversized payloads
- `ekino/phpstan-banned-code` enforces no eval/exec/shell_exec/system

### Quality

- PHPStan Level 8 with exception checking
- PHP-CS-Fixer (PER-CS:risky)
- PHPMD with customized ruleset
- Rector (PHP 8.4 sets)
- Deptrac architecture enforcement (7 layers, 0 violations)
- 100% Mutation Score (Infection)
- 151 tests, 464 assertions
- PHP 8.4+ with strict types
- Immutable value objects throughout (`final readonly class`)

[1.0.0]:
  https://github.com/marcstraube/zappzarapp-php-audit-logger/releases/tag/v1.0.0
