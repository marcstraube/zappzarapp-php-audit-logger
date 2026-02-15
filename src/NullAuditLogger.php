<?php

declare(strict_types=1);

namespace Zappzarapp\AuditLogger;

/**
 * Null Object Audit Logger - No-op implementation
 *
 * Use for environments where audit logging is not required.
 * Implements AuditLoggerInterface but performs no operations.
 */
final readonly class NullAuditLogger implements AuditLoggerInterface
{
    public function log(AuditLogEntry $entry): void
    {
    }

    public function logAuth(
        string $action,
        ?int $userId = null,
        array $data = [],
        string $ipAddress = 'unknown',
        string $userAgent = 'unknown',
    ): void {
    }

    public function logAdmin(
        string $action,
        int $adminUserId,
        string $entityType,
        string|int $entityId,
        array $data = [],
        string $ipAddress = 'unknown',
        string $userAgent = 'unknown',
    ): void {
    }

    /**
     * @return AuditLogResult[]
     */
    /** @infection-ignore-all: NullAuditLogger ignores all parameters */
    public function getLogsForEntity(
        string $entityType,
        string|int $entityId,
        int $limit = 100,
    ): array {
        return [];
    }

    /**
     * @return AuditLogResult[]
     */
    /** @infection-ignore-all: NullAuditLogger ignores all parameters */
    public function getLogsForUser(
        int $userId,
        int $limit = 100,
    ): array {
        return [];
    }

    /**
     * @return AuditLogResult[]
     */
    public function readFileLog(): array
    {
        return [];
    }

    public function verify(AuditLogResult $result): bool
    {
        return false;
    }
}
