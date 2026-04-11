<?php

declare(strict_types=1);

namespace Zappzarapp\AuditLogger;

use DateMalformedStringException;
use DateTimeImmutable;
use Zappzarapp\AuditLogger\Exception\StorageException;

/**
 * Maps normalized row data to AuditLogResult DTOs
 *
 * Shared mapping logic used by both AuditLogger (database) and FileLogReader (file fallback).
 */
final class ResultMapper
{
    private const array REQUIRED_KEYS = [
        'id',
        'timestamp',
        'user_id',
        'ip_address',
        'user_agent',
        'action',
        'entity_type',
        'entity_id',
        'checksum',
    ];

    /**
     * Map a normalized row to an AuditLogResult
     *
     * @param array<string, mixed> $row Normalized row containing all required keys
     * @param string $errorContext Context for error messages (e.g. 'audit log row', 'file log line 5')
     * @param string|null $dataError Error message when data JSON was corrupt
     *
     * @throws StorageException
     */
    public static function map(array $row, string $errorContext, ?string $dataError = null): AuditLogResult
    {
        self::validateSchema($row, $errorContext);

        return new AuditLogResult(
            id: (int) $row['id'],
            timestamp: self::parseTimestamp((string) $row['timestamp'], $errorContext),
            /** @infection-ignore-all: CastInt is defensive — value is always int from DB/JSON */
            userId: $row['user_id'] !== null ? (int) $row['user_id'] : null,
            ipAddress: (string) $row['ip_address'],
            userAgent: (string) $row['user_agent'],
            action: (string) $row['action'],
            entityType: (string) $row['entity_type'],
            entityId: (string) $row['entity_id'],
            data: is_array($row['data'] ?? null) ? $row['data'] : null,
            checksum: (string) $row['checksum'],
            dataError: $dataError,
        );
    }

    /**
     * @param array<string, mixed> $row
     *
     * @throws StorageException
     */
    private static function validateSchema(array $row, string $errorContext): void
    {
        $missingKeys = array_diff(self::REQUIRED_KEYS, array_keys($row));
        if ($missingKeys !== []) {
            throw new StorageException('Missing required fields in ' . $errorContext . ': ' . implode(', ', $missingKeys));
        }
    }

    /**
     * @throws StorageException
     */
    private static function parseTimestamp(string $timestamp, string $errorContext): DateTimeImmutable
    {
        try {
            return new DateTimeImmutable($timestamp);
        } catch (DateMalformedStringException $dateMalformedStringException) {
            throw new StorageException(
                'Invalid timestamp in ' . $errorContext . ': ' . $dateMalformedStringException->getMessage(),
                0,
                $dateMalformedStringException,
            );
        }
    }
}
