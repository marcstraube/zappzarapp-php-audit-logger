<?php

/** @noinspection PhpMultipleClassDeclarationsInspection */

declare(strict_types=1);

namespace Zappzarapp\AuditLogger;

use DateMalformedStringException;
use DateTimeImmutable;
use JsonException;
use Zappzarapp\AuditLogger\Encryption\EncryptionInterface;
use Zappzarapp\AuditLogger\Exception\EncryptionException;
use Zappzarapp\AuditLogger\Exception\StorageException;

/**
 * Reads and decrypts audit log entries from the file-based fallback log
 */
final readonly class FileLogReader
{
    public function __construct(
        private EncryptionInterface $fileEncryption,
        private string $encryptionKey,
        private ?string $logFilePath = null,
    ) {}

    /**
     * Read all audit log entries from the file log
     *
     * @return AuditLogResult[]
     *
     * @throws EncryptionException
     * @throws StorageException
     */
    public function readFileLog(): array
    {
        if ($this->logFilePath === null || !file_exists($this->logFilePath)) {
            return [];
        }

        $content = file_get_contents($this->logFilePath);
        /** @infection-ignore-all: trim is defensive — file_put_contents always appends PHP_EOL */
        if ($content === false || trim($content) === '') {
            return [];
        }

        $lines   = explode(PHP_EOL, trim($content));
        $results = [];

        foreach ($lines as $index => $line) {
            $results[] = $this->mapFileLogLine($line, $index + 1);
        }

        return $results;
    }

    /**
     * Map a single encrypted file log line to an AuditLogResult
     *
     * @throws EncryptionException
     * @throws StorageException
     */
    private function mapFileLogLine(string $encryptedLine, int $lineNumber): AuditLogResult
    {
        $decrypted = $this->fileEncryption->decrypt($encryptedLine, $this->encryptionKey);

        try {
            /** @infection-ignore-all: json_decode depth 512 is standard, ±1 has no effect */
            $row = json_decode($decrypted, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $jsonException) {
            throw new StorageException(
                'Corrupted JSON in file log line ' . $lineNumber . ': ' . $jsonException->getMessage(),
                0,
                $jsonException,
            );
        }

        if (!is_array($row)) {
            throw new StorageException('Corrupted JSON in file log line ' . $lineNumber . ': expected object');
        }

        $requiredKeys = ['timestamp', 'user_id', 'ip_address', 'user_agent', 'action', 'entity_type', 'entity_id', 'checksum'];
        $missingKeys  = array_diff($requiredKeys, array_keys($row));
        if ($missingKeys !== []) {
            throw new StorageException('Missing required fields in file log line ' . $lineNumber . ': ' . implode(', ', $missingKeys));
        }

        try {
            $timestamp = new DateTimeImmutable((string) $row['timestamp']);
        } catch (DateMalformedStringException $dateMalformedStringException) {
            throw new StorageException(
                'Invalid timestamp in file log line ' . $lineNumber . ': ' . $dateMalformedStringException->getMessage(),
                0,
                $dateMalformedStringException,
            );
        }

        return new AuditLogResult(
            id: $lineNumber,
            timestamp: $timestamp,
            /** @infection-ignore-all: CastInt is defensive — json_decode already returns int for JSON integers */
            userId: $row['user_id'] !== null ? (int) $row['user_id'] : null,
            ipAddress: (string) $row['ip_address'],
            userAgent: (string) $row['user_agent'],
            action: (string) $row['action'],
            entityType: (string) $row['entity_type'],
            entityId: (string) $row['entity_id'],
            data: is_array($row['data'] ?? null) ? $row['data'] : null,
            checksum: (string) $row['checksum'],
        );
    }
}
