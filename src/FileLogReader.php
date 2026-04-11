<?php

/** @noinspection PhpMultipleClassDeclarationsInspection */

declare(strict_types=1);

namespace Zappzarapp\AuditLogger;

use JsonException;
use Zappzarapp\AuditLogger\Encryption\EncryptionInterface;
use Zappzarapp\AuditLogger\Exception\EncryptionException;
use Zappzarapp\AuditLogger\Exception\StorageException;

/**
 * Reads and decrypts audit log entries from the file-based fallback log
 */
final readonly class FileLogReader
{
    private const int MAX_FILE_LOG_SIZE = 10_485_760;

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

        $fileSize = filesize($this->logFilePath);
        if ($fileSize === false || $fileSize > self::MAX_FILE_LOG_SIZE) {
            throw new StorageException(
                'File log exceeds maximum size of ' . self::MAX_FILE_LOG_SIZE . ' bytes',
            );
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

        $row['id'] = $lineNumber;

        return ResultMapper::map($row, 'file log line ' . $lineNumber);
    }
}
