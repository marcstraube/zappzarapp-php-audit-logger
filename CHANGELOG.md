# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
