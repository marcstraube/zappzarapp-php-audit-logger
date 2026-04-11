<?php

/** @noinspection PhpMultipleClassDeclarationsInspection */
/** @noinspection PhpParenthesesCanBeOmittedForNewCallInspection PHPMD/PDepend cannot parse new Foo()->method() syntax */

declare(strict_types=1);

namespace Zappzarapp\AuditLogger;

use DateMalformedStringException;
use DateTimeImmutable;
use InvalidArgumentException;
use JsonException;
use PDO;
use PDOException;
use Zappzarapp\AuditLogger\Encryption\AppEncryption;
use Zappzarapp\AuditLogger\Encryption\DatabaseEncryption;
use Zappzarapp\AuditLogger\Encryption\EncryptionInterface;
use Zappzarapp\AuditLogger\Exception\AuditLogException;
use Zappzarapp\AuditLogger\Exception\EncryptionException;
use Zappzarapp\AuditLogger\Exception\StorageException;

/**
 * GDPR-compliant audit logger with encrypted data storage and tamper-proof checksums
 *
 * Supports both application-level encryption (AppEncryption) and
 * database-level encryption (DatabaseEncryption via SQL functions).
 */
final readonly class AuditLogger implements AuditLoggerInterface
{
    private const string DB_HKDF_INFO = 'audit-logger-db-encryption';

    private const string HMAC_HKDF_INFO = 'audit-logger-hmac';

    private const int MAX_ENCODED_DATA_SIZE = 10_000;

    private bool $useDbEncryption;

    private EncryptionInterface $fileEncryption;

    private FileLogReader $fileLogReader;

    private string $dbEncryptionKey;

    private string $hmacKey;

    /**
     * @param PDO $pdo Database connection
     * @param string $encryptionKey Encryption key for sensitive data
     * @param EncryptionInterface $encryption Encryption strategy (default: AppEncryption)
     * @param string $tableName Database table name (default: 'audit_logs')
     * @param string|null $logFilePath File path for redundant logging (null = no file logging)
     * @param int|null $maxLimit Optional upper bound for query limit parameter
     *
     * @throws InvalidArgumentException
     * @throws StorageException
     */
    public function __construct(
        private PDO $pdo,
        private string $encryptionKey,
        private EncryptionInterface $encryption = new AppEncryption(),
        private string $tableName = 'audit_logs',
        private ?string $logFilePath = null,
        private ?int $maxLimit = null,
    ) {
        if (strlen($encryptionKey) < 32) {
            throw new InvalidArgumentException('Encryption key must be at least 32 bytes');
        }

        if ($this->maxLimit !== null && $this->maxLimit < 1) {
            throw new InvalidArgumentException('Max limit must be at least 1');
        }

        $this->escapeIdentifier($tableName);

        $this->useDbEncryption  = $encryption instanceof DatabaseEncryption;
        $this->fileEncryption   = $this->useDbEncryption ? new AppEncryption() : $encryption;
        $this->fileLogReader    = new FileLogReader($this->fileEncryption, $encryptionKey, $logFilePath);
        $this->dbEncryptionKey  = $this->useDbEncryption
            ? hash_hkdf('sha256', $encryptionKey, 32, self::DB_HKDF_INFO)
            : '';
        $this->hmacKey          = hash_hkdf('sha256', $encryptionKey, 32, self::HMAC_HKDF_INFO);
    }

    /**
     * @inheritDoc
     */
    public function log(AuditLogEntry $entry): void
    {
        $timestamp = (new DateTimeImmutable())->format('Y-m-d H:i:s');
        $dataJson  = $this->encodeData($entry, $timestamp);

        if (strlen($dataJson) > self::MAX_ENCODED_DATA_SIZE) {
            throw new StorageException(
                'Encoded audit data exceeds maximum size of ' . self::MAX_ENCODED_DATA_SIZE
                . ' bytes (got ' . strlen($dataJson) . ' bytes)',
            );
        }

        $checksum  = $this->calculateChecksum($timestamp, $entry, $dataJson);

        try {
            $this->writeToDatabase($timestamp, $entry, $dataJson, $checksum);
        } catch (PDOException $pdoException) {
            try {
                $this->writeToFile($timestamp, $entry, $checksum);
            } catch (AuditLogException $fileException) {
                throw new StorageException(
                    'Failed to write audit log to database AND file fallback: '
                        . $pdoException->getMessage()
                        . ' | File fallback error: ' . $fileException->getMessage(),
                    0,
                    $pdoException,
                );
            }

            throw new StorageException('Failed to write audit log to database: ' . $pdoException->getMessage(), 0, $pdoException);
        }

        try {
            $this->writeToFile($timestamp, $entry, $checksum);
        } catch (AuditLogException) {
            // Silently ignore file write failures after successful database write.
            // The file log is a redundant fallback — the audit entry is already persisted.
        }
    }

    /**
     * @inheritDoc
     */
    public function logAuth(
        string $action,
        ?int $userId = null,
        array $data = [],
        string $ipAddress = 'unknown',
        string $userAgent = 'unknown',
    ): void {
        $this->log(new AuditLogEntry(
            action: $action,
            entityType: 'auth',
            entityId: (string) ($userId ?? 0),
            userId: $userId,
            ipAddress: $ipAddress,
            userAgent: $userAgent,
            data: $data,
        ));
    }

    /**
     * @inheritDoc
     */
    public function logAdmin(
        string $action,
        int $adminUserId,
        string $entityType,
        string|int $entityId,
        array $data = [],
        string $ipAddress = 'unknown',
        string $userAgent = 'unknown',
    ): void {
        $data['admin_user_id'] = $adminUserId;
        $this->log(new AuditLogEntry(
            action: $action,
            entityType: $entityType,
            entityId: $entityId,
            userId: $adminUserId,
            ipAddress: $ipAddress,
            userAgent: $userAgent,
            data: $data,
        ));
    }

    /**
     * @inheritDoc
     */
    public function getLogsForEntity(
        string $entityType,
        string|int $entityId,
        int $limit = 100,
    ): array {
        return $this->queryLogs(
            'entity_type = :entity_type AND entity_id = :entity_id',
            [
                ':entity_type' => [$entityType],
                ':entity_id'   => [(string) $entityId],
            ],
            $limit,
        );
    }

    /**
     * @inheritDoc
     */
    public function getLogsForUser(
        int $userId,
        int $limit = 100,
    ): array {
        return $this->queryLogs(
            'user_id = :user_id',
            [
                ':user_id' => [$userId, PDO::PARAM_INT],
            ],
            $limit,
        );
    }

    /**
     * @inheritDoc
     */
    public function verify(AuditLogResult $result): bool
    {
        try {
            $dataJson = json_encode([
                'meta' => [
                    'user_agent' => $result->userAgent,
                    'timestamp'  => $result->timestamp->format('Y-m-d H:i:s'),
                ],
                'data' => $result->data,
            ], JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return false;
        }

        $expected = hash_hmac(
            'sha256',
            $this->buildChecksumInput(
                $result->timestamp->format('Y-m-d H:i:s'),
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
     * @inheritDoc
     */
    public function readFileLog(): array
    {
        return $this->fileLogReader->readFileLog();
    }

    /**
     * @throws StorageException
     */
    private function encodeData(AuditLogEntry $entry, string $timestamp): string
    {
        try {
            return json_encode([
                'meta' => [
                    'user_agent' => $entry->userAgent,
                    'timestamp'  => $timestamp,
                ],
                'data' => $entry->data,
            ], JSON_THROW_ON_ERROR);
        } catch (JsonException $jsonException) {
            throw new StorageException('Failed to encode audit data as JSON: ' . $jsonException->getMessage(), 0, $jsonException);
        }
    }

    private function calculateChecksum(string $timestamp, AuditLogEntry $entry, string $dataJson): string
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

    /**
     * @throws PDOException
     * @throws EncryptionException
     * @throws StorageException
     */
    private function writeToDatabase(
        string $timestamp,
        AuditLogEntry $entry,
        string $dataJson,
        string $checksum,
    ): void {
        $table = $this->escapeIdentifier($this->tableName);

        if ($this->useDbEncryption) {
            $sql = "
                INSERT INTO {$table} (timestamp, user_id, ip_address, action, entity_type, entity_id, data, checksum)
                VALUES (:timestamp, :user_id, :ip_address, :action, :entity_type, :entity_id, encrypt_text(:data, :encryption_key), :checksum)
            ";
        } else {
            $sql = "
                INSERT INTO {$table} (timestamp, user_id, ip_address, action, entity_type, entity_id, data, checksum)
                VALUES (:timestamp, :user_id, :ip_address, :action, :entity_type, :entity_id, :data, :checksum)
            ";
        }

        $stmt = $this->pdo->prepare($sql);

        $params = [
            'timestamp'   => $timestamp,
            'user_id'     => $entry->userId,
            'ip_address'  => $entry->ipAddress,
            'action'      => $entry->action,
            'entity_type' => $entry->entityType,
            'entity_id'   => (string) $entry->entityId,
            'checksum'    => $checksum,
        ];

        if ($this->useDbEncryption) {
            $params['data']           = $dataJson;
            $params['encryption_key'] = $this->dbEncryptionKey;
        } else {
            $params['data'] = $this->encryption->encrypt($dataJson, $this->encryptionKey);
        }

        $stmt->execute($params);
    }

    /**
     * @throws EncryptionException
     * @throws StorageException
     */
    private function writeToFile(string $timestamp, AuditLogEntry $entry, string $checksum): void
    {
        if ($this->logFilePath === null) {
            return;
        }

        $logDir = dirname($this->logFilePath);
        /** @infection-ignore-all: Permission value and mkdir failure path untestable without filesystem mocking */
        if (!is_dir($logDir) && (!mkdir($logDir, 0755, true) && !is_dir($logDir))) {
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

        $result = file_put_contents($this->logFilePath, $encrypted . PHP_EOL, FILE_APPEND | LOCK_EX);

        if ($result === false) {
            throw new StorageException('Failed to write audit log to file: ' . $this->logFilePath);
        }

        if ($isNewFile) {
            chmod($this->logFilePath, 0600);
        }
    }

    /**
     * @param array<string, mixed> $params
     * @return AuditLogResult[]
     *
     * @throws InvalidArgumentException
     * @throws EncryptionException
     * @throws StorageException
     */
    private function queryLogs(string $whereClause, array $params, int $limit): array
    {
        if ($limit < 1) {
            throw new InvalidArgumentException('Limit must be at least 1');
        }

        if ($this->maxLimit !== null && $limit > $this->maxLimit) {
            throw new InvalidArgumentException('Limit must not exceed ' . $this->maxLimit);
        }

        $table = $this->escapeIdentifier($this->tableName);

        if ($this->useDbEncryption) {
            $sql = "
                SELECT id, timestamp, user_id, ip_address, action, entity_type, entity_id,
                       decrypt_text(data, :encryption_key) as data_decrypted, checksum
                FROM {$table}
                WHERE {$whereClause}
                ORDER BY timestamp DESC
                LIMIT :limit
            ";
        } else {
            $sql = "
                SELECT id, timestamp, user_id, ip_address, action, entity_type, entity_id,
                       data, checksum
                FROM {$table}
                WHERE {$whereClause}
                ORDER BY timestamp DESC
                LIMIT :limit
            ";
        }

        try {
            $stmt = $this->pdo->prepare($sql);

            foreach ($params as $name => $value) {
                $stmt->bindValue($name, ...$value);
            }

            $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);

            if ($this->useDbEncryption) {
                $stmt->bindValue(':encryption_key', $this->dbEncryptionKey);
            }

            $stmt->execute();
            $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
        } catch (PDOException $pdoException) {
            throw new StorageException('Failed to query audit logs: ' . $pdoException->getMessage(), 0, $pdoException);
        }

        return $this->mapResults($rows);
    }

    /**
     * Map raw database rows to AuditLogResult DTOs
     *
     * @param array<int, array<string, mixed>> $rows
     * @return AuditLogResult[]
     *
     * @throws EncryptionException
     * @throws StorageException
     */
    private function mapResults(array $rows): array
    {
        return array_map($this->mapRow(...), $rows);
    }

    /**
     * @param array<string, mixed> $row
     *
     * @throws EncryptionException
     * @throws StorageException
     */
    private function mapRow(array $row): AuditLogResult
    {
        $this->validateRowSchema($row);

        $dataString = $this->useDbEncryption
            ? ($row['data_decrypted'] ?? null)
            : ($row['data'] !== null ? $this->encryption->decrypt((string) $row['data'], $this->encryptionKey) : null);

        $data      = null;
        $dataError = null;
        $userAgent = 'unknown';
        /** @infection-ignore-all: LogicalAnd equivalent — try/catch handles null/empty identically */
        if ($dataString !== null && $dataString !== '') {
            try {
                /** @infection-ignore-all: json_decode depth 512 is standard, ±1 has no effect */
                $decoded = json_decode((string) $dataString, true, 512, JSON_THROW_ON_ERROR);
                if (is_array($decoded)) {
                    /** @infection-ignore-all: CastString is defensive — value is always string from JSON */
                    $userAgent = (string) ($decoded['meta']['user_agent'] ?? 'unknown');
                    $data      = $decoded['data'] ?? null;
                }
            } catch (JsonException $jsonException) {
                $dataError = 'Corrupted JSON data: ' . $jsonException->getMessage();
            }
        }

        try {
            $timestamp = new DateTimeImmutable((string) $row['timestamp']);
        } catch (DateMalformedStringException $dateMalformedStringException) {
            throw new StorageException('Invalid timestamp in audit log: ' . $dateMalformedStringException->getMessage(), 0, $dateMalformedStringException);
        }

        return new AuditLogResult(
            id: (int) $row['id'],
            timestamp: $timestamp,
            userId: $row['user_id'] !== null ? (int) $row['user_id'] : null,
            ipAddress: (string) $row['ip_address'],
            userAgent: $userAgent,
            action: (string) $row['action'],
            entityType: (string) $row['entity_type'],
            entityId: (string) $row['entity_id'],
            data: $data,
            checksum: (string) $row['checksum'],
            dataError: $dataError,
        );
    }

    /**
     * Validate that a database row contains all required fields
     *
     * @param array<string, mixed> $row
     *
     * @throws StorageException
     */
    private function validateRowSchema(array $row): void
    {
        $requiredKeys = ['id', 'timestamp', 'user_id', 'ip_address', 'action', 'entity_type', 'entity_id', 'checksum'];
        $missingKeys  = array_diff($requiredKeys, array_keys($row));
        if ($missingKeys !== []) {
            throw new StorageException('Missing required fields in audit log row: ' . implode(', ', $missingKeys));
        }
    }

    /**
     * Escape a SQL identifier (table name) to prevent injection
     *
     * @throws StorageException
     */
    private function escapeIdentifier(string $identifier): string
    {
        if (preg_match('/^[a-zA-Z_]\w*$/', $identifier) !== 1) {
            throw new StorageException('Invalid table name: ' . $identifier);
        }

        return $identifier;
    }
}
