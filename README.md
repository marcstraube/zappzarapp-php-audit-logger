# zappzarapp/audit-logger

[![Latest Version](https://img.shields.io/packagist/v/zappzarapp/audit-logger.svg)](https://packagist.org/packages/zappzarapp/audit-logger)
[![PHP Version](https://img.shields.io/packagist/php-v/zappzarapp/audit-logger.svg)](https://packagist.org/packages/zappzarapp/audit-logger)
[![License](https://img.shields.io/packagist/l/zappzarapp/audit-logger.svg)](https://packagist.org/packages/zappzarapp/audit-logger)
[![CI](https://github.com/marcstraube/zappzarapp-php-audit-logger/actions/workflows/ci.yml/badge.svg)](https://github.com/marcstraube/zappzarapp-php-audit-logger/actions/workflows/ci.yml)
[![Socket Badge](https://badge.socket.dev/composer/package/zappzarapp/audit-logger)](https://socket.dev/composer/package/zappzarapp/audit-logger)

GDPR-compliant audit logging for PHP with injectable encryption, configurable
storage, and tamper-proof checksums.

## Features

- **GDPR compliant** - Supports Art. 15, 17, 30, 32, 33
- **Injectable encryption** - AppEncryption (AES-256-GCM) or DatabaseEncryption
- **Tamper-proof** - HMAC-SHA-256 checksums with `verify()` method
- **Configurable** - Custom table name, optional file logging
- **Null Object** - `NullAuditLogger` for environments without audit requirements
- **Zero dependencies** - Only requires `ext-pdo` (stdlib)
- **Both PostgreSQL and MariaDB** - Migration SQL included

## Installation

```bash
composer require zappzarapp/audit-logger
```

## Quick Start

```php
use Zappzarapp\AuditLogger\AuditLogger;
use Zappzarapp\AuditLogger\AuditLogEntry;

$auditLogger = new AuditLogger(
    pdo: $pdo,
    encryptionKey: $_ENV['ENCRYPTION_KEY'],
);

// Log a data access event
$auditLogger->log(new AuditLogEntry(
    action: 'user.view',
    entityType: 'user',
    entityId: 123,
    userId: $currentUserId,
    ipAddress: $request->getClientIp(),
    userAgent: $request->getUserAgent(),
));

// Log authentication
$auditLogger->logAuth(
    action: 'login.success',
    userId: $userId,
    ipAddress: $request->getClientIp(),
    userAgent: $request->getUserAgent(),
);

// Log admin action
$auditLogger->logAdmin(
    action: 'role.granted',
    adminUserId: $adminId,
    entityType: 'user',
    entityId: $targetUserId,
    data: ['role' => 'moderator'],
);

// Query logs
$logs = $auditLogger->getLogsForEntity('user', 123);
$userLogs = $auditLogger->getLogsForUser($userId);

// Verify integrity
foreach ($logs as $log) {
    if (!$auditLogger->verify($log)) {
        // Tampered entry detected!
    }
}
```

## Configuration

```php
use Zappzarapp\AuditLogger\AuditLogger;
use Zappzarapp\AuditLogger\Encryption\AppEncryption;
use Zappzarapp\AuditLogger\Encryption\DatabaseEncryption;

// Full configuration
$auditLogger = new AuditLogger(
    pdo: $pdo,
    encryptionKey: $_ENV['ENCRYPTION_KEY'],
    encryption: new AppEncryption(),    // default (AES-256-GCM in PHP)
    tableName: 'audit_logs',            // default table name
    logFilePath: '/var/log/audit.log',  // optional file logging (null = disabled)
);

// Using database-level encryption (for existing encrypt_text() setups)
$auditLogger = new AuditLogger(
    pdo: $pdo,
    encryptionKey: $_ENV['ENCRYPTION_KEY'],
    encryption: new DatabaseEncryption(),
);

// Disable audit logging (Null Object pattern)
$auditLogger = new NullAuditLogger();
```

> **Note:** File logging (`logFilePath`) does not include log rotation. Configure
> external rotation (e.g. `logrotate`) to prevent unbounded file growth.
>
> Example `/etc/logrotate.d/audit-logger`:
>
> ```text
> /var/log/audit.log {
>     daily
>     rotate 90
>     compress
>     delaycompress
>     missingok
>     notifempty
>     copytruncate
> }
> ```

> **Note:** The library does not set query timeouts on the injected PDO connection.
> Configure timeouts at the connection level to prevent indefinite blocking:
>
> ```php
> // PostgreSQL
> $pdo->exec('SET statement_timeout = 5000'); // 5 seconds
>
> // MariaDB / MySQL
> $pdo = new PDO($dsn, $user, $pass, [
>     PDO::ATTR_TIMEOUT => 5,
> ]);
> ```

## Database Setup

Apply the migration for your database:

- **PostgreSQL:** `migrations/postgresql/audit_logs.sql`
- **MariaDB:** `migrations/mariadb/audit_logs.sql`

## Documentation

- [GDPR Compliance](docs/gdpr-compliance.md) - GDPR articles covered, purge/retention guidance
- [Database Encryption](docs/database-encryption.md) - Migration from DB-level encryption

## Development

```bash
make install    # Install dependencies
make test       # Run tests
make analyse    # PHPStan static analysis
make cs-check   # Code style check
make check      # All quality checks
make check-full # Including mutation testing
```

## License

MIT
