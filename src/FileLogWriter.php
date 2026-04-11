<?php

declare(strict_types=1);

namespace Zappzarapp\AuditLogger;

use JsonException;
use Zappzarapp\AuditLogger\Encryption\EncryptionInterface;
use Zappzarapp\AuditLogger\Exception\EncryptionException;
use Zappzarapp\AuditLogger\Exception\StorageException;

/**
 * Writes encrypted audit log entries to the file-based fallback log
 */
final readonly class FileLogWriter
{
    public function __construct(
        private EncryptionInterface $fileEncryption,
        private string $encryptionKey,
        private ?string $logFilePath,
    ) {}

    /**
     * Write an audit log entry to the file log
     *
     * @throws EncryptionException
     * @throws StorageException
     */
    public function write(string $timestamp, AuditLogEntry $entry, string $checksum): void
    {
        if ($this->logFilePath === null) {
            return;
        }

        $logDir = dirname($this->logFilePath);
        /** @infection-ignore-all: Permission value and mkdir failure path untestable without filesystem mocking */
        if (!is_dir($logDir) && (!mkdir($logDir, 0700, true) && !is_dir($logDir))) {
            throw new StorageException('Failed to create log directory: ' . $logDir);
        }

        try {
            $logEntry = json_encode([
                'timestamp'   => $timestamp,
                'user_id'     => $entry->userId,
                'ip_address'  => $entry->ipAddress,
                'user_agent'  => $entry->userAgent,
                'action'      => $entry->action,
                'entity_type' => $entry->entityType,
                'entity_id'   => (string) $entry->entityId,
                'data'        => $entry->data,
                'checksum'    => $checksum,
            ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        } catch (JsonException $jsonException) {
            throw new StorageException('Failed to encode file log entry as JSON: ' . $jsonException->getMessage(), 0, $jsonException);
        }

        $encrypted = $this->fileEncryption->encrypt($logEntry, $this->encryptionKey);

        /** @infection-ignore-all: Permission value and isNewFile check not meaningfully mutatable */
        $isNewFile = !file_exists($this->logFilePath);

        /** @infection-ignore-all: Concat swap ($encrypted . PHP_EOL vs PHP_EOL . $encrypted) — functionally equivalent after trim in FileLogReader */
        $result = file_put_contents($this->logFilePath, $encrypted . PHP_EOL, FILE_APPEND | LOCK_EX);

        if ($result === false) {
            throw new StorageException('Failed to write audit log to file: ' . $this->logFilePath);
        }

        if ($isNewFile) {
            chmod($this->logFilePath, 0600);
        }
    }
}
