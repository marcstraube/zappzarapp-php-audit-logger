<?php

declare(strict_types=1);

namespace Zappzarapp\AuditLogger\Tests;

use InvalidArgumentException;
use PDO;
use PDOException;
use PDOStatement;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\AuditLogger\AuditLogger;
use Zappzarapp\AuditLogger\AuditLogResult;
use Zappzarapp\AuditLogger\Encryption\AppEncryption;
use Zappzarapp\AuditLogger\Encryption\DatabaseEncryption;
use Zappzarapp\AuditLogger\Exception\StorageException;

#[CoversClass(AuditLogger::class)]
final class AuditLoggerReadTest extends TestCase
{
    private string $encryptionKey;

    protected function setUp(): void
    {
        parent::setUp();
        $this->encryptionKey = 'test-encryption-key-32-characters!';
    }

    #[Test]
    public function testGetLogsForEntityWithAppEncryptionDecryptsInPhp(): void
    {
        $encryption = new AppEncryption();
        $testData   = ['test' => 'data'];
        $envelope   = ['meta' => ['user_agent' => 'unknown', 'timestamp' => '2026-02-13 12:00:00'], 'data' => $testData];
        $encrypted  = $encryption->encrypt((string) json_encode($envelope), $this->encryptionKey);

        $stmt = $this->createMock(PDOStatement::class);
        $stmt->expects($this->once())
            ->method('execute')
            ->willReturn(true);
        $stmt->expects($this->once())
            ->method('fetchAll')
            ->willReturn([
                [
                    'id'          => 1,
                    'timestamp'   => '2026-02-13 12:00:00',
                    'user_id'     => 42,
                    'ip_address'  => '127.0.0.1',
                    'action'      => 'user.view',
                    'entity_type' => 'user',
                    'entity_id'   => '42',
                    'data'        => $encrypted,
                    'checksum'    => 'abc123',
                ],
            ]);

        $pdo = $this->createMock(PDO::class);
        $pdo->expects($this->once())
            ->method('prepare')
            ->with($this->logicalAnd(
                $this->stringContains('SELECT'),
                $this->logicalNot($this->stringContains('decrypt_text'))
            ))
            ->willReturn($stmt);

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: $encryption,
        );

        $results = $logger->getLogsForEntity(entityType: 'user', entityId: 42);

        $this->assertCount(1, $results);
        $this->assertInstanceOf(AuditLogResult::class, $results[0]);
        $this->assertSame(1, $results[0]->id);
        $this->assertSame('user.view', $results[0]->action);
        $this->assertSame('user', $results[0]->entityType);
        $this->assertSame('42', $results[0]->entityId);
        $this->assertSame($testData, $results[0]->data);
        $this->assertNull($results[0]->dataError);
    }

    #[Test]
    public function testGetLogsForEntityWithDatabaseEncryptionUsesDecryptTextFunction(): void
    {
        $testData = ['test' => 'data'];
        $envelope = ['meta' => ['user_agent' => 'TestBrowser/2.0', 'timestamp' => '2026-02-13 12:00:00'], 'data' => $testData];

        $boundValues = [];
        $stmt        = $this->createMock(PDOStatement::class);
        $stmt->expects($this->once())
            ->method('execute')
            ->willReturn(true);
        $stmt->expects($this->once())
            ->method('fetchAll')
            ->willReturn([
                [
                    'id'              => 1,
                    'timestamp'       => '2026-02-13 12:00:00',
                    'user_id'         => 42,
                    'ip_address'      => '127.0.0.1',
                    'action'          => 'user.view',
                    'entity_type'     => 'user',
                    'entity_id'       => '42',
                    'data_decrypted'  => json_encode($envelope),
                    'checksum'        => 'abc123',
                ],
            ]);
        $stmt->method('bindValue')
            ->willReturnCallback(function (string $param, mixed $value) use (&$boundValues): true {
                $boundValues[$param] = $value;
                return true;
            });

        $pdo = $this->createMock(PDO::class);
        $pdo->expects($this->once())
            ->method('prepare')
            ->with($this->stringContains('decrypt_text(data, :encryption_key)'))
            ->willReturn($stmt);

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: new DatabaseEncryption(),
        );

        $results = $logger->getLogsForEntity(entityType: 'user', entityId: 42);

        $this->assertCount(1, $results);
        $this->assertSame($testData, $results[0]->data);
        $this->assertSame('TestBrowser/2.0', $results[0]->userAgent);
        $this->assertArrayHasKey(':encryption_key', $boundValues);
        $expectedDbKey = hash_hkdf('sha256', $this->encryptionKey, 32, 'audit-logger-db-encryption');
        $this->assertSame($expectedDbKey, $boundValues[':encryption_key']);
    }

    #[Test]
    public function testGetLogsForUserWithAppEncryption(): void
    {
        $encryption = new AppEncryption();
        $testData   = ['action_type' => 'view'];
        $envelope   = ['meta' => ['user_agent' => 'unknown', 'timestamp' => '2026-02-13 13:00:00'], 'data' => $testData];
        $encrypted  = $encryption->encrypt((string) json_encode($envelope), $this->encryptionKey);

        $stmt = $this->createMock(PDOStatement::class);
        $stmt->expects($this->once())
            ->method('execute')
            ->willReturn(true);
        $stmt->expects($this->once())
            ->method('fetchAll')
            ->willReturn([
                [
                    'id'          => 2,
                    'timestamp'   => '2026-02-13 13:00:00',
                    'user_id'     => 99,
                    'ip_address'  => '192.168.1.1',
                    'action'      => 'profile.update',
                    'entity_type' => 'profile',
                    'entity_id'   => '99',
                    'data'        => $encrypted,
                    'checksum'    => 'def456',
                ],
            ]);

        $pdo = $this->createMock(PDO::class);
        $pdo->expects($this->once())
            ->method('prepare')
            ->with($this->logicalAnd(
                $this->stringContains('WHERE user_id = :user_id'),
                $this->logicalNot($this->stringContains('decrypt_text'))
            ))
            ->willReturn($stmt);

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: $encryption,
        );

        $results = $logger->getLogsForUser(userId: 99);

        $this->assertCount(1, $results);
        $this->assertSame(99, $results[0]->userId);
        $this->assertSame('profile.update', $results[0]->action);
        $this->assertSame($testData, $results[0]->data);
    }

    #[Test]
    public function testGetLogsForUserWithDatabaseEncryption(): void
    {
        $testData = ['action_type' => 'delete'];
        $envelope = ['meta' => ['user_agent' => 'unknown', 'timestamp' => '2026-02-13 14:00:00'], 'data' => $testData];

        $stmt = $this->createMock(PDOStatement::class);
        $stmt->expects($this->once())
            ->method('execute')
            ->willReturn(true);
        $stmt->expects($this->once())
            ->method('fetchAll')
            ->willReturn([
                [
                    'id'             => 3,
                    'timestamp'      => '2026-02-13 14:00:00',
                    'user_id'        => 55,
                    'ip_address'     => '10.0.0.1',
                    'action'         => 'user.delete',
                    'entity_type'    => 'user',
                    'entity_id'      => '55',
                    'data_decrypted' => json_encode($envelope),
                    'checksum'       => 'ghi789',
                ],
            ]);

        $pdo = $this->createMock(PDO::class);
        $pdo->expects($this->once())
            ->method('prepare')
            ->with($this->stringContains('decrypt_text(data, :encryption_key)'))
            ->willReturn($stmt);

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: new DatabaseEncryption(),
        );

        $results = $logger->getLogsForUser(userId: 55);

        $this->assertCount(1, $results);
        $this->assertSame($testData, $results[0]->data);
    }

    #[Test]
    public function testCustomTableNameInSelectQueries(): void
    {
        $stmt = $this->createMock(PDOStatement::class);
        $stmt->expects($this->once())
            ->method('execute')
            ->willReturn(true);
        $stmt->expects($this->once())
            ->method('fetchAll')
            ->willReturn([]);

        $pdo = $this->createMock(PDO::class);
        $pdo->expects($this->once())
            ->method('prepare')
            ->with($this->stringContains('FROM custom_logs'))
            ->willReturn($stmt);

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: new DatabaseEncryption(),
            tableName: 'custom_logs',
        );

        $logger->getLogsForEntity(entityType: 'user', entityId: 1);
    }

    #[Test]
    public function testGetLogsForEntityThrowsStorageExceptionOnPdoError(): void
    {
        $pdo = $this->createMock(PDO::class);
        $pdo->expects($this->once())
            ->method('prepare')
            ->willThrowException(new PDOException('Query failed'));

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: new DatabaseEncryption(),
        );

        $this->expectException(StorageException::class);
        $this->expectExceptionMessage('Failed to query audit logs');

        $logger->getLogsForEntity(entityType: 'user', entityId: 1);
    }

    #[Test]
    public function testGetLogsForEntityThrowsStorageExceptionOnInvalidTimestamp(): void
    {
        $stmt = $this->createMock(PDOStatement::class);
        $stmt->expects($this->once())
            ->method('execute')
            ->willReturn(true);
        $stmt->expects($this->once())
            ->method('fetchAll')
            ->willReturn([
                [
                    'id'             => 1,
                    'timestamp'      => 'not-a-valid-date',
                    'user_id'        => 1,
                    'ip_address'     => '127.0.0.1',
                    'action'         => 'test',
                    'entity_type'    => 'test',
                    'entity_id'      => '1',
                    'data_decrypted' => '{"key":"value"}',
                    'checksum'       => 'abc',
                ],
            ]);

        $pdo = $this->createMock(PDO::class);
        $pdo->expects($this->once())
            ->method('prepare')
            ->willReturn($stmt);

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: new DatabaseEncryption(),
        );

        $this->expectException(StorageException::class);
        $this->expectExceptionMessage('Invalid timestamp in audit log row');

        $logger->getLogsForEntity(entityType: 'test', entityId: 1);
    }

    /**
     * Test that query exception includes the PDO error message (kills mutants #43, #44).
     */
    #[Test]
    public function testGetLogsForEntityExceptionIncludesPdoMessage(): void
    {
        $pdo = $this->createMock(PDO::class);
        $pdo->expects($this->once())
            ->method('prepare')
            ->willThrowException(new PDOException('Connection timeout'));

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: new DatabaseEncryption(),
        );

        try {
            $logger->getLogsForEntity(entityType: 'user', entityId: 1);
            $this->fail('Expected StorageException was not thrown');
        } catch (StorageException $storageException) {
            $this->assertStringStartsWith('Failed to query audit logs: ', $storageException->getMessage());
            $this->assertStringContainsString('Connection timeout', $storageException->getMessage());
            $this->assertSame(0, $storageException->getCode());
            $this->assertInstanceOf(PDOException::class, $storageException->getPrevious());
        }
    }

    /**
     * Test invalid timestamp exception includes the error message (kills mutants #48, #49, #50, #51).
     */
    #[Test]
    public function testInvalidTimestampExceptionIncludesMessage(): void
    {
        $stmt = $this->createMock(PDOStatement::class);
        $stmt->expects($this->once())
            ->method('execute')
            ->willReturn(true);
        $stmt->expects($this->once())
            ->method('fetchAll')
            ->willReturn([
                [
                    'id'             => 1,
                    'timestamp'      => 'not-a-valid-date',
                    'user_id'        => 1,
                    'ip_address'     => '127.0.0.1',
                    'action'         => 'test',
                    'entity_type'    => 'test',
                    'entity_id'      => '1',
                    'data_decrypted' => '{"key":"value"}',
                    'checksum'       => 'abc',
                ],
            ]);

        $pdo = $this->createMock(PDO::class);
        $pdo->expects($this->once())
            ->method('prepare')
            ->willReturn($stmt);

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: new DatabaseEncryption(),
        );

        try {
            $logger->getLogsForEntity(entityType: 'test', entityId: 1);
            $this->fail('Expected StorageException was not thrown');
        } catch (StorageException $storageException) {
            $this->assertStringStartsWith('Invalid timestamp in audit log row: ', $storageException->getMessage());
            $this->assertSame(0, $storageException->getCode());
            // The exception message should include the DateMalformedStringException message
            $this->assertGreaterThan(
                strlen('Invalid timestamp in audit log row: '),
                strlen($storageException->getMessage()),
            );
        }
    }

    /**
     * Test getLogsForEntity passes correct parameters (kills mutants #21-24).
     */
    #[Test]
    public function testGetLogsForEntityPassesCorrectParams(): void
    {
        $capturedBindings = [];

        $stmt = $this->createMock(PDOStatement::class);
        $stmt->expects($this->atLeastOnce())
            ->method('bindValue')
            ->willReturnCallback(function (string $name, mixed $value) use (&$capturedBindings): bool {
                $capturedBindings[$name] = $value;
                return true;
            });
        $stmt->expects($this->once())
            ->method('execute')
            ->willReturn(true);
        $stmt->expects($this->once())
            ->method('fetchAll')
            ->willReturn([]);

        $pdo = $this->createMock(PDO::class);
        $pdo->expects($this->once())
            ->method('prepare')
            ->willReturn($stmt);

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: new DatabaseEncryption(),
        );

        $logger->getLogsForEntity(entityType: 'user', entityId: 42, limit: 50);

        $this->assertSame('user', $capturedBindings[':entity_type']);
        $this->assertSame('42', $capturedBindings[':entity_id']);
        $this->assertSame(50, $capturedBindings[':limit']);
    }

    /**
     * Test getLogsForEntity uses string cast on entityId (kills mutant #24: CastString removal).
     */
    #[Test]
    public function testGetLogsForEntityCastsEntityIdToString(): void
    {
        $capturedBindings = [];

        $stmt = $this->createMock(PDOStatement::class);
        $stmt->expects($this->atLeastOnce())
            ->method('bindValue')
            ->willReturnCallback(function (string $name, mixed $value) use (&$capturedBindings): bool {
                $capturedBindings[$name] = $value;
                return true;
            });
        $stmt->expects($this->once())
            ->method('execute')
            ->willReturn(true);
        $stmt->expects($this->once())
            ->method('fetchAll')
            ->willReturn([]);

        $pdo = $this->createMock(PDO::class);
        $pdo->expects($this->once())
            ->method('prepare')
            ->willReturn($stmt);

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: new DatabaseEncryption(),
        );

        // Pass int entityId - should be cast to string
        $logger->getLogsForEntity(entityType: 'user', entityId: 42);

        $this->assertIsString($capturedBindings[':entity_id']);
        $this->assertSame('42', $capturedBindings[':entity_id']);
    }

    /**
     * Test getLogsForUser passes correct parameters (kills mutants #25-28).
     */
    #[Test]
    public function testGetLogsForUserPassesCorrectParams(): void
    {
        $capturedBindings = [];

        $stmt = $this->createMock(PDOStatement::class);
        $stmt->expects($this->atLeastOnce())
            ->method('bindValue')
            ->willReturnCallback(function (string $name, mixed $value) use (&$capturedBindings): bool {
                $capturedBindings[$name] = $value;
                return true;
            });
        $stmt->expects($this->once())
            ->method('execute')
            ->willReturn(true);
        $stmt->expects($this->once())
            ->method('fetchAll')
            ->willReturn([]);

        $pdo = $this->createMock(PDO::class);
        $pdo->expects($this->once())
            ->method('prepare')
            ->willReturn($stmt);

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: new DatabaseEncryption(),
        );

        $logger->getLogsForUser(userId: 99, limit: 50);

        $this->assertSame(99, $capturedBindings[':user_id']);
        $this->assertSame(50, $capturedBindings[':limit']);
    }

    /**
     * Test getLogsForUser uses default limit of 100 (kills mutants #25, #26).
     */
    #[Test]
    public function testGetLogsForUserUsesDefaultLimit(): void
    {
        $capturedBindings = [];

        $stmt = $this->createMock(PDOStatement::class);
        $stmt->expects($this->atLeastOnce())
            ->method('bindValue')
            ->willReturnCallback(function (string $name, mixed $value) use (&$capturedBindings): bool {
                $capturedBindings[$name] = $value;
                return true;
            });
        $stmt->expects($this->once())
            ->method('execute')
            ->willReturn(true);
        $stmt->expects($this->once())
            ->method('fetchAll')
            ->willReturn([]);

        $pdo = $this->createMock(PDO::class);
        $pdo->expects($this->once())
            ->method('prepare')
            ->willReturn($stmt);

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: new DatabaseEncryption(),
        );

        $logger->getLogsForUser(userId: 99);

        $this->assertSame(100, $capturedBindings[':limit']);
    }

    /**
     * Test getLogsForEntity uses default limit of 100 (kills mutants #21, #22).
     */
    #[Test]
    public function testGetLogsForEntityUsesDefaultLimit(): void
    {
        $capturedBindings = [];

        $stmt = $this->createMock(PDOStatement::class);
        $stmt->expects($this->atLeastOnce())
            ->method('bindValue')
            ->willReturnCallback(function (string $name, mixed $value) use (&$capturedBindings): bool {
                $capturedBindings[$name] = $value;
                return true;
            });
        $stmt->expects($this->once())
            ->method('execute')
            ->willReturn(true);
        $stmt->expects($this->once())
            ->method('fetchAll')
            ->willReturn([]);

        $pdo = $this->createMock(PDO::class);
        $pdo->expects($this->once())
            ->method('prepare')
            ->willReturn($stmt);

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: new DatabaseEncryption(),
        );

        $logger->getLogsForEntity(entityType: 'user', entityId: 1);

        $this->assertSame(100, $capturedBindings[':limit']);
    }

    /**
     * Test mapResults correctly casts userId to int (kills mutant #52: CastInt removal).
     */
    #[Test]
    public function testMapResultsCastsUserIdToInt(): void
    {
        $stmt = $this->createMock(PDOStatement::class);
        $stmt->expects($this->once())
            ->method('execute')
            ->willReturn(true);
        $stmt->expects($this->once())
            ->method('fetchAll')
            ->willReturn([
                [
                    'id'             => '1',
                    'timestamp'      => '2026-02-13 12:00:00',
                    'user_id'        => '42', // string from DB
                    'ip_address'     => '127.0.0.1',
                    'action'         => 'user.view',
                    'entity_type'    => 'user',
                    'entity_id'      => '42',
                    'data_decrypted' => null,
                    'checksum'       => 'abc',
                ],
            ]);

        $pdo = $this->createMock(PDO::class);
        $pdo->expects($this->once())
            ->method('prepare')
            ->willReturn($stmt);

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: new DatabaseEncryption(),
        );

        $results = $logger->getLogsForEntity(entityType: 'user', entityId: 42);

        $this->assertCount(1, $results);
        $this->assertIsInt($results[0]->userId);
        $this->assertSame(42, $results[0]->userId);
    }

    /**
     * Test mapResults handles null data from database (kills mutant #47: LogicalAnd to Or).
     */
    #[Test]
    public function testMapResultsHandlesNullData(): void
    {
        $stmt = $this->createMock(PDOStatement::class);
        $stmt->expects($this->once())
            ->method('execute')
            ->willReturn(true);
        $stmt->expects($this->once())
            ->method('fetchAll')
            ->willReturn([
                [
                    'id'             => 1,
                    'timestamp'      => '2026-02-13 12:00:00',
                    'user_id'        => 42,
                    'ip_address'     => '127.0.0.1',
                    'action'         => 'user.view',
                    'entity_type'    => 'user',
                    'entity_id'      => '42',
                    'data_decrypted' => null,
                    'checksum'       => 'abc',
                ],
            ]);

        $pdo = $this->createMock(PDO::class);
        $pdo->expects($this->once())
            ->method('prepare')
            ->willReturn($stmt);

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: new DatabaseEncryption(),
        );

        $results = $logger->getLogsForEntity(entityType: 'user', entityId: 42);

        $this->assertCount(1, $results);
        $this->assertNull($results[0]->data);
        $this->assertSame('unknown', $results[0]->userAgent);
        $this->assertNull($results[0]->dataError);
    }

    /**
     * Test mapResults handles empty string data (kills mutant #47: LogicalAnd to Or).
     */
    #[Test]
    public function testMapResultsHandlesEmptyStringData(): void
    {
        $stmt = $this->createMock(PDOStatement::class);
        $stmt->expects($this->once())
            ->method('execute')
            ->willReturn(true);
        $stmt->expects($this->once())
            ->method('fetchAll')
            ->willReturn([
                [
                    'id'             => 1,
                    'timestamp'      => '2026-02-13 12:00:00',
                    'user_id'        => 42,
                    'ip_address'     => '127.0.0.1',
                    'action'         => 'user.view',
                    'entity_type'    => 'user',
                    'entity_id'      => '42',
                    'data_decrypted' => '',
                    'checksum'       => 'abc',
                ],
            ]);

        $pdo = $this->createMock(PDO::class);
        $pdo->expects($this->once())
            ->method('prepare')
            ->willReturn($stmt);

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: new DatabaseEncryption(),
        );

        $results = $logger->getLogsForEntity(entityType: 'user', entityId: 42);

        $this->assertCount(1, $results);
        $this->assertNull($results[0]->data);
        $this->assertSame('unknown', $results[0]->userAgent);
        $this->assertNull($results[0]->dataError);
    }

    /**
     * Test mapRow handles corrupted (non-JSON) decrypted data gracefully and exposes error via dataError.
     */
    #[Test]
    public function testMapRowHandlesCorruptedJsonData(): void
    {
        $stmt = $this->createMock(PDOStatement::class);
        $stmt->expects($this->once())
            ->method('execute')
            ->willReturn(true);
        $stmt->expects($this->once())
            ->method('fetchAll')
            ->willReturn([
                [
                    'id'             => 1,
                    'timestamp'      => '2026-02-13 12:00:00',
                    'user_id'        => 42,
                    'ip_address'     => '127.0.0.1',
                    'action'         => 'user.view',
                    'entity_type'    => 'user',
                    'entity_id'      => '42',
                    'data_decrypted' => 'not-valid-json{',
                    'checksum'       => 'abc',
                ],
            ]);

        $pdo = $this->createMock(PDO::class);
        $pdo->expects($this->once())
            ->method('prepare')
            ->willReturn($stmt);

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: new DatabaseEncryption(),
        );

        $results = $logger->getLogsForEntity(entityType: 'user', entityId: 42);

        $this->assertCount(1, $results);
        $this->assertNull($results[0]->data);
        $this->assertSame('unknown', $results[0]->userAgent);
        $this->assertNotNull($results[0]->dataError);
        $this->assertStringStartsWith('Corrupted JSON data: ', $results[0]->dataError);
    }

    /**
     * Test getLogsForUser exception includes PDO message (kills mutants #45, #46).
     */
    #[Test]
    public function testGetLogsForUserExceptionIncludesPdoMessage(): void
    {
        $pdo = $this->createMock(PDO::class);
        $pdo->expects($this->once())
            ->method('prepare')
            ->willThrowException(new PDOException('User query failed'));

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: new DatabaseEncryption(),
        );

        try {
            $logger->getLogsForUser(userId: 1);
            $this->fail('Expected StorageException was not thrown');
        } catch (StorageException $storageException) {
            $this->assertStringStartsWith('Failed to query audit logs: ', $storageException->getMessage());
            $this->assertStringContainsString('User query failed', $storageException->getMessage());
            $this->assertSame(0, $storageException->getCode());
        }
    }

    /**
     * Test mapRow throws StorageException when required fields are missing from DB row.
     */
    #[Test]
    public function testMapRowThrowsStorageExceptionOnMissingFields(): void
    {
        $stmt = $this->createMock(PDOStatement::class);
        $stmt->expects($this->once())
            ->method('execute')
            ->willReturn(true);
        $stmt->expects($this->once())
            ->method('fetchAll')
            ->willReturn([
                [
                    'id'             => 1,
                    // 'timestamp' is missing
                    'user_id'        => 42,
                    'ip_address'     => '127.0.0.1',
                    'action'         => 'user.view',
                    'entity_type'    => 'user',
                    'entity_id'      => '42',
                    'data_decrypted' => null,
                    // 'checksum' is missing
                ],
            ]);

        $pdo = $this->createMock(PDO::class);
        $pdo->expects($this->once())
            ->method('prepare')
            ->willReturn($stmt);

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: new DatabaseEncryption(),
        );

        try {
            $logger->getLogsForEntity(entityType: 'user', entityId: 42);
            $this->fail('Expected StorageException was not thrown');
        } catch (StorageException $storageException) {
            $this->assertStringStartsWith('Missing required fields in audit log row: ', $storageException->getMessage());
            $this->assertStringContainsString('timestamp', $storageException->getMessage());
            $this->assertStringContainsString('checksum', $storageException->getMessage());
        }
    }

    /**
     * Test mapRow detects missing 'id' field (kills ArrayItemRemoval mutant on requiredKeys).
     */
    #[Test]
    public function testMapRowThrowsStorageExceptionOnMissingId(): void
    {
        $stmt = $this->createMock(PDOStatement::class);
        $stmt->expects($this->once())
            ->method('execute')
            ->willReturn(true);
        $stmt->expects($this->once())
            ->method('fetchAll')
            ->willReturn([
                [
                    // 'id' is missing
                    'timestamp'      => '2026-02-13 12:00:00',
                    'user_id'        => 42,
                    'ip_address'     => '127.0.0.1',
                    'action'         => 'user.view',
                    'entity_type'    => 'user',
                    'entity_id'      => '42',
                    'data_decrypted' => null,
                    'checksum'       => 'abc',
                ],
            ]);

        $pdo = $this->createMock(PDO::class);
        $pdo->expects($this->once())
            ->method('prepare')
            ->willReturn($stmt);

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: new DatabaseEncryption(),
        );

        try {
            $logger->getLogsForEntity(entityType: 'user', entityId: 42);
            $this->fail('Expected StorageException was not thrown');
        } catch (StorageException $storageException) {
            $this->assertStringContainsString('id', $storageException->getMessage());
        }
    }

    #[Test]
    public function testGetLogsForEntityRejectsZeroLimit(): void
    {
        $pdo = $this->createStub(PDO::class);

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: new DatabaseEncryption(),
        );

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Limit must be at least 1');

        $logger->getLogsForEntity(entityType: 'user', entityId: 1, limit: 0);
    }

    #[Test]
    public function testGetLogsForEntityRejectsNegativeLimit(): void
    {
        $pdo = $this->createStub(PDO::class);

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: new DatabaseEncryption(),
        );

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Limit must be at least 1');

        $logger->getLogsForEntity(entityType: 'user', entityId: 1, limit: -5);
    }

    #[Test]
    public function testGetLogsForUserRejectsZeroLimit(): void
    {
        $pdo = $this->createStub(PDO::class);

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: new DatabaseEncryption(),
        );

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Limit must be at least 1');

        $logger->getLogsForUser(userId: 1, limit: 0);
    }

    #[Test]
    public function testGetLogsForUserRejectsNegativeLimit(): void
    {
        $pdo = $this->createStub(PDO::class);

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: new DatabaseEncryption(),
        );

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Limit must be at least 1');

        $logger->getLogsForUser(userId: 1, limit: -10);
    }

    #[Test]
    public function testConstructorRejectsZeroMaxLimit(): void
    {
        $pdo = $this->createStub(PDO::class);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Max limit must be at least 1');

        new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            maxLimit: 0,
        );
    }

    #[Test]
    public function testConstructorRejectsNegativeMaxLimit(): void
    {
        $pdo = $this->createStub(PDO::class);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Max limit must be at least 1');

        new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            maxLimit: -1,
        );
    }

    #[Test]
    public function testGetLogsForEntityRejectsLimitExceedingMaxLimit(): void
    {
        $pdo = $this->createStub(PDO::class);

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: new DatabaseEncryption(),
            maxLimit: 50,
        );

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Limit must not exceed 50');

        $logger->getLogsForEntity(entityType: 'user', entityId: 1, limit: 51);
    }

    #[Test]
    public function testGetLogsForUserRejectsLimitExceedingMaxLimit(): void
    {
        $pdo = $this->createStub(PDO::class);

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: new DatabaseEncryption(),
            maxLimit: 50,
        );

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Limit must not exceed 50');

        $logger->getLogsForUser(userId: 1, limit: 51);
    }

    /**
     * Boundary test: limit exactly at maxLimit must be accepted.
     */
    #[Test]
    public function testGetLogsForEntityAcceptsLimitAtMaxLimit(): void
    {
        $capturedBindings = [];

        $stmt = $this->createMock(PDOStatement::class);
        $stmt->expects($this->atLeastOnce())
            ->method('bindValue')
            ->willReturnCallback(function (string $name, mixed $value) use (&$capturedBindings): bool {
                $capturedBindings[$name] = $value;
                return true;
            });
        $stmt->expects($this->once())
            ->method('execute')
            ->willReturn(true);
        $stmt->expects($this->once())
            ->method('fetchAll')
            ->willReturn([]);

        $pdo = $this->createMock(PDO::class);
        $pdo->expects($this->once())
            ->method('prepare')
            ->willReturn($stmt);

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: new DatabaseEncryption(),
            maxLimit: 50,
        );

        $logger->getLogsForEntity(entityType: 'user', entityId: 1, limit: 50);

        $this->assertSame(50, $capturedBindings[':limit']);
    }

    #[Test]
    public function testMaxLimitNullAllowsAnyLimit(): void
    {
        $capturedBindings = [];

        $stmt = $this->createMock(PDOStatement::class);
        $stmt->expects($this->atLeastOnce())
            ->method('bindValue')
            ->willReturnCallback(function (string $name, mixed $value) use (&$capturedBindings): bool {
                $capturedBindings[$name] = $value;
                return true;
            });
        $stmt->expects($this->once())
            ->method('execute')
            ->willReturn(true);
        $stmt->expects($this->once())
            ->method('fetchAll')
            ->willReturn([]);

        $pdo = $this->createMock(PDO::class);
        $pdo->expects($this->once())
            ->method('prepare')
            ->willReturn($stmt);

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: new DatabaseEncryption(),
        );

        $logger->getLogsForEntity(entityType: 'user', entityId: 1, limit: 10_000);

        $this->assertSame(10_000, $capturedBindings[':limit']);
    }

    /**
     * Test that limit=1 is accepted (boundary, kills mutant < to <=).
     */
    #[Test]
    public function testGetLogsForEntityAcceptsLimitOfOne(): void
    {
        $capturedBindings = [];

        $stmt = $this->createMock(PDOStatement::class);
        $stmt->expects($this->atLeastOnce())
            ->method('bindValue')
            ->willReturnCallback(function (string $name, mixed $value) use (&$capturedBindings): bool {
                $capturedBindings[$name] = $value;
                return true;
            });
        $stmt->expects($this->once())
            ->method('execute')
            ->willReturn(true);
        $stmt->expects($this->once())
            ->method('fetchAll')
            ->willReturn([]);

        $pdo = $this->createMock(PDO::class);
        $pdo->expects($this->once())
            ->method('prepare')
            ->willReturn($stmt);

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: new DatabaseEncryption(),
        );

        $logger->getLogsForEntity(entityType: 'user', entityId: 1, limit: 1);

        $this->assertSame(1, $capturedBindings[':limit']);
    }
}
