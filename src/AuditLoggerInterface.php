<?php

declare(strict_types=1);

namespace Zappzarapp\AuditLogger;

use InvalidArgumentException;
use Zappzarapp\AuditLogger\Exception\AuditLogException;

/**
 * Audit Logger Interface for GDPR-compliant audit logging
 *
 * GDPR Art. 30: Records of processing activities
 * GDPR Art. 32: Security measures (logging access to personal data)
 */
interface AuditLoggerInterface
{
    /**
     * Log an audit event
     *
     * @throws AuditLogException
     * @throws InvalidArgumentException
     */
    public function log(AuditLogEntry $entry): void;

    /**
     * Log authentication event
     *
     * @param string $action Action performed (e.g., 'login.success', 'login.failed')
     * @param int|null $userId User ID (null for failed login attempts)
     * @param array<string, mixed> $data Additional data
     * @param string $ipAddress Client IP address
     * @param string $userAgent Client user agent
     *
     * @throws AuditLogException
     * @throws InvalidArgumentException
     */
    public function logAuth(
        string $action,
        ?int $userId = null,
        array $data = [],
        string $ipAddress = 'unknown',
        string $userAgent = 'unknown',
    ): void;

    /**
     * Log administrative action
     *
     * @param string $action Action performed (e.g., 'role.granted')
     * @param int $adminUserId Administrator who performed the action
     * @param string $entityType Entity type affected
     * @param string|int $entityId Entity ID affected
     * @param array<string, mixed> $data Additional data
     * @param string $ipAddress Client IP address
     * @param string $userAgent Client user agent
     *
     * @throws AuditLogException
     * @throws InvalidArgumentException
     */
    public function logAdmin(
        string $action,
        int $adminUserId,
        string $entityType,
        string|int $entityId,
        array $data = [],
        string $ipAddress = 'unknown',
        string $userAgent = 'unknown',
    ): void;

    /**
     * Retrieve audit logs for a specific entity
     *
     * @return AuditLogResult[]
     *
     * @throws AuditLogException
     * @throws InvalidArgumentException
     */
    public function getLogsForEntity(
        string $entityType,
        string|int $entityId,
        int $limit = 100,
    ): array;

    /**
     * Retrieve audit logs for a specific user
     *
     * @return AuditLogResult[]
     *
     * @throws AuditLogException
     * @throws InvalidArgumentException
     */
    public function getLogsForUser(
        int $userId,
        int $limit = 100,
    ): array;

    /**
     * Read audit log entries from the file log (fallback recovery)
     *
     * @return AuditLogResult[]
     *
     * @throws AuditLogException
     */
    public function readFileLog(): array;

    /**
     * Verify the integrity of an audit log entry by recalculating its checksum
     */
    public function verify(AuditLogResult $result): bool;
}
