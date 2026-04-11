<?php

declare(strict_types=1);

namespace Zappzarapp\AuditLogger;

use JsonException;
use Zappzarapp\AuditLogger\Exception\StorageException;

/**
 * Calculates and verifies HMAC-SHA256 checksums for audit log integrity
 */
final readonly class ChecksumCalculator
{
    public const string TIMESTAMP_FORMAT = 'Y-m-d H:i:s';

    private const string HMAC_HKDF_INFO = 'audit-logger-hmac';

    public function __construct(private string $hmacKey) {}

    public static function deriveKey(string $encryptionKey): string
    {
        return hash_hkdf('sha256', $encryptionKey, 32, self::HMAC_HKDF_INFO);
    }

    /**
     * Encode audit entry data as JSON envelope
     *
     * @throws StorageException
     */
    public function encodeData(AuditLogEntry $entry, string $timestamp): string
    {
        try {
            return json_encode(
                $this->buildEnvelope($entry->userAgent, $timestamp, $entry->data),
                JSON_THROW_ON_ERROR,
            );
        } catch (JsonException $jsonException) {
            throw new StorageException('Failed to encode audit data as JSON: ' . $jsonException->getMessage(), 0, $jsonException);
        }
    }

    /**
     * Calculate HMAC-SHA256 checksum for an audit log entry
     */
    public function calculate(string $timestamp, AuditLogEntry $entry, string $dataJson): string
    {
        return hash_hmac(
            'sha256',
            $this->buildChecksumInput(
                $timestamp,
                $entry->userId,
                $entry->ipAddress,
                $entry->action,
                $entry->entityType,
                (string) $entry->entityId,
                $dataJson,
            ),
            $this->hmacKey,
        );
    }

    /**
     * Verify the integrity of an audit log result by recalculating its checksum
     */
    public function verify(AuditLogResult $result): bool
    {
        if ($result->dataError !== null) {
            /** @infection-ignore-all: ReturnRemoval — removing return still yields false (HMAC mismatch), early-return is an optimisation */
            return false;
        }

        try {
            $dataJson = json_encode(
                $this->buildEnvelope(
                    $result->userAgent,
                    $result->timestamp->format(self::TIMESTAMP_FORMAT),
                    $result->data,
                ),
                JSON_THROW_ON_ERROR,
            );
        } catch (JsonException) {
            return false;
        }

        $expected = hash_hmac(
            'sha256',
            $this->buildChecksumInput(
                $result->timestamp->format(self::TIMESTAMP_FORMAT),
                $result->userId,
                $result->ipAddress,
                $result->action,
                $result->entityType,
                $result->entityId,
                $dataJson,
            ),
            $this->hmacKey,
        );

        return hash_equals($expected, $result->checksum);
    }

    /**
     * @param array<string, mixed>|null $data
     * @return array{meta: array{user_agent: string, timestamp: string}, data: array<string, mixed>|null}
     */
    private function buildEnvelope(string $userAgent, string $timestamp, ?array $data): array
    {
        return [
            'meta' => [
                'user_agent' => $userAgent,
                'timestamp'  => $timestamp,
            ],
            'data' => $data,
        ];
    }

    private function buildChecksumInput(
        string $timestamp,
        ?int $userId,
        string $ipAddress,
        string $action,
        string $entityType,
        string $entityId,
        string $dataJson,
    ): string {
        return $timestamp . "\0"
            . ($userId ?? '') . "\0"
            . $ipAddress . "\0"
            . $action . "\0"
            . $entityType . "\0"
            . $entityId . "\0"
            . $dataJson;
    }
}
