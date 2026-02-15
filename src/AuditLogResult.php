<?php

declare(strict_types=1);

namespace Zappzarapp\AuditLogger;

use DateTimeImmutable;

/**
 * Immutable DTO representing an audit log entry read from storage
 */
final readonly class AuditLogResult
{
    /**
     * @param int $id Database row ID
     * @param DateTimeImmutable $timestamp When the action was performed
     * @param int|null $userId User who performed the action
     * @param string $ipAddress Client IP address
     * @param string $userAgent Client user agent
     * @param string $action Action performed
     * @param string $entityType Entity type
     * @param string $entityId Entity ID
     * @param array<string, mixed>|null $data Decrypted user-provided context data (null if decryption failed or data was corrupt)
     * @param string $checksum HMAC-SHA256 tamper-proof checksum
     * @param string|null $dataError Error message when data JSON was corrupt (null = no error)
     */
    public function __construct(
        public int $id,
        public DateTimeImmutable $timestamp,
        public ?int $userId,
        public string $ipAddress,
        public string $userAgent,
        public string $action,
        public string $entityType,
        public string $entityId,
        public ?array $data,
        public string $checksum,
        public ?string $dataError = null,
    ) {}
}
