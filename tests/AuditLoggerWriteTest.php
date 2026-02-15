<?php

declare(strict_types=1);

namespace Zappzarapp\AuditLogger\Tests;

use InvalidArgumentException;
use JsonException;
use org\bovigo\vfs\vfsStream;
use PDO;
use PDOException;
use PDOStatement;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;
use Zappzarapp\AuditLogger\AuditLogEntry;
use Zappzarapp\AuditLogger\AuditLogger;
use Zappzarapp\AuditLogger\Encryption\AppEncryption;
use Zappzarapp\AuditLogger\Encryption\DatabaseEncryption;
use Zappzarapp\AuditLogger\Encryption\EncryptionInterface;
use Zappzarapp\AuditLogger\Exception\EncryptionException;
use Zappzarapp\AuditLogger\Exception\StorageException;

#[CoversClass(AuditLogger::class)]
final class AuditLoggerWriteTest extends TestCase
{
    private string $encryptionKey;

    private string $tempLogFile;

    protected function setUp(): void
    {
        parent::setUp();
        $this->encryptionKey = 'test-encryption-key-32-characters!';
        $this->tempLogFile   = sys_get_temp_dir() . '/audit-test-' . uniqid() . '.log';
    }

    protected function tearDown(): void
    {
        if (file_exists($this->tempLogFile)) {
            unlink($this->tempLogFile);
        }

        parent::tearDown();
    }

    #[Test]
    public function testLogWithAppEncryptionWritesToDatabase(): void
    {
        $encryption = $this->createMock(EncryptionInterface::class);
        $encryption->expects($this->once())
            ->method('encrypt')
            ->willReturn('encrypted-data');

        $stmt = $this->createMock(PDOStatement::class);
        $stmt->expects($this->once())
            ->method('execute')
            ->willReturn(true);

        $pdo = $this->createMock(PDO::class);
        $pdo->expects($this->once())
            ->method('prepare')
            ->with($this->stringContains('INSERT INTO audit_logs'))
            ->willReturn($stmt);

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: $encryption,
        );

        $entry = new AuditLogEntry(
            action: 'user.login',
            entityType: 'user',
            entityId: 42,
            userId: 42,
            ipAddress: '127.0.0.1',
            userAgent: 'PHPUnit/12',
            data: ['status' => 'success'],
        );

        $logger->log($entry);
    }

    #[Test]
    public function testLogWithAppEncryptionDoesNotUseEncryptTextFunction(): void
    {
        $encryption = $this->createMock(EncryptionInterface::class);
        $encryption->expects($this->once())
            ->method('encrypt')
            ->willReturn('encrypted-data');

        $stmt = $this->createMock(PDOStatement::class);
        $stmt->expects($this->once())
            ->method('execute')
            ->willReturn(true);

        $pdo = $this->createMock(PDO::class);
        $pdo->expects($this->once())
            ->method('prepare')
            ->with($this->logicalAnd(
                $this->stringContains('INSERT INTO audit_logs'),
                $this->logicalNot($this->stringContains('encrypt_text'))
            ))
            ->willReturn($stmt);

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: $encryption,
        );

        $entry = new AuditLogEntry(
            action: 'user.login',
            entityType: 'user',
            entityId: 42,
        );

        $logger->log($entry);
    }

    #[Test]
    public function testLogWithDatabaseEncryptionUsesEncryptTextFunction(): void
    {
        $stmt = $this->createMock(PDOStatement::class);
        $stmt->expects($this->once())
            ->method('execute')
            ->willReturn(true);

        $pdo = $this->createMock(PDO::class);
        $pdo->expects($this->once())
            ->method('prepare')
            ->with($this->stringContains('encrypt_text(:data, :encryption_key)'))
            ->willReturn($stmt);

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: new DatabaseEncryption(),
        );

        $entry = new AuditLogEntry(
            action: 'user.login',
            entityType: 'user',
            entityId: 42,
        );

        $logger->log($entry);
    }

    #[Test]
    public function testLogOnPdoExceptionWritesToFileAndThrowsStorageException(): void
    {
        $pdo = $this->createMock(PDO::class);
        $pdo->expects($this->once())
            ->method('prepare')
            ->willThrowException(new PDOException('Database connection failed'));

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: new DatabaseEncryption(),
            logFilePath: $this->tempLogFile,
        );

        $entry = new AuditLogEntry(
            action: 'user.login',
            entityType: 'user',
            entityId: 42,
            userId: 42,
            ipAddress: '127.0.0.1',
        );

        try {
            $logger->log($entry);
            $this->fail('Expected StorageException was not thrown');
        } catch (StorageException $storageException) {
            $this->assertStringStartsWith('Failed to write audit log to database: ', $storageException->getMessage());
            $this->assertStringContainsString('Database connection failed', $storageException->getMessage());
            $this->assertStringNotContainsString('AND file fallback', $storageException->getMessage());
            $this->assertSame(0, $storageException->getCode());
            $this->assertInstanceOf(PDOException::class, $storageException->getPrevious());
        }

        // Verify file was written as emergency fallback (kills mutant #14)
        $this->assertFileExists($this->tempLogFile);
    }

    #[Test]
    public function testLogOnPdoExceptionAndFileFallbackFailureThrowsCombinedException(): void
    {
        $encryption = $this->createMock(EncryptionInterface::class);
        $encryption->expects($this->once())
            ->method('encrypt')
            ->willThrowException(new EncryptionException('Encryption failed'));

        $pdo = $this->createMock(PDO::class);
        $pdo->expects($this->once())
            ->method('prepare')
            ->willThrowException(new PDOException('Database connection failed'));

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: $encryption,
            logFilePath: $this->tempLogFile,
        );

        $entry = new AuditLogEntry(
            action: 'user.login',
            entityType: 'user',
            entityId: 42,
        );

        try {
            $logger->log($entry);
            $this->fail('Expected StorageException was not thrown');
        } catch (StorageException $storageException) {
            $message = $storageException->getMessage();
            $this->assertStringStartsWith('Failed to write audit log to database AND file fallback: ', $message);
            $this->assertStringContainsString('Database connection failed', $message);
            $this->assertStringContainsString(' | File fallback error: ', $message);
            $this->assertStringContainsString('Encryption failed', $message);
            // Verify ordering: PDO message before file error (kills Concat mutants)
            $pdoPos  = strpos($message, 'Database connection failed');
            $filePos = strpos($message, 'File fallback error:');
            $encPos  = strpos($message, 'Encryption failed');
            $this->assertNotFalse($pdoPos);
            $this->assertNotFalse($filePos);
            $this->assertNotFalse($encPos);
            $this->assertLessThan($filePos, $pdoPos);
            $this->assertLessThan($encPos, $filePos);
            $this->assertSame(0, $storageException->getCode());
            $this->assertInstanceOf(PDOException::class, $storageException->getPrevious());
        }
    }

    #[Test]
    public function testLogWritesToFileForRedundancy(): void
    {
        $stmt = $this->createMock(PDOStatement::class);
        $stmt->expects($this->once())
            ->method('execute')
            ->willReturn(true);

        $pdo = $this->createMock(PDO::class);
        $pdo->expects($this->once())
            ->method('prepare')
            ->willReturn($stmt);

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: new DatabaseEncryption(),
            logFilePath: $this->tempLogFile,
        );

        $entry = new AuditLogEntry(
            action: 'user.logout',
            entityType: 'user',
            entityId: 99,
            userId: 99,
            ipAddress: '192.168.1.1',
            userAgent: 'TestAgent/1.0',
            data: ['reason' => 'manual'],
        );

        $logger->log($entry);

        // Verify file was written
        $this->assertFileExists($this->tempLogFile);
        $content = file_get_contents($this->tempLogFile);
        $this->assertNotFalse($content);

        // Content is encrypted, not plain JSON
        $this->assertNull(json_decode(trim($content), true));

        // Decrypt and verify contents
        $encryption = new AppEncryption();
        $decrypted  = $encryption->decrypt(trim($content), $this->encryptionKey);
        $logEntry   = json_decode($decrypted, true);
        $this->assertIsArray($logEntry);
        $this->assertSame('user.logout', $logEntry['action']);
        $this->assertSame('user', $logEntry['entity_type']);
        $this->assertSame('99', $logEntry['entity_id']);
        $this->assertSame(99, $logEntry['user_id']);
        $this->assertSame('192.168.1.1', $logEntry['ip_address']);
        $this->assertSame('TestAgent/1.0', $logEntry['user_agent']);
        $this->assertSame(['reason' => 'manual'], $logEntry['data']);
        $this->assertArrayHasKey('checksum', $logEntry);
        $this->assertNotEmpty($logEntry['checksum']);
    }

    #[Test]
    public function testLogDoesNotWriteFileWhenLogFilePathIsNull(): void
    {
        $stmt = $this->createMock(PDOStatement::class);
        $stmt->expects($this->once())
            ->method('execute')
            ->willReturn(true);

        $pdo = $this->createMock(PDO::class);
        $pdo->expects($this->once())
            ->method('prepare')
            ->willReturn($stmt);

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: new DatabaseEncryption(),
            logFilePath: null, // No file logging
        );

        $entry = new AuditLogEntry(
            action: 'user.login',
            entityType: 'user',
            entityId: 1,
        );

        $logger->log($entry);

        // Verify no file was written
        $this->assertFileDoesNotExist($this->tempLogFile);
    }

    #[Test]
    public function testLogAuthCreatesAuditLogEntryWithEntityTypeAuth(): void
    {
        $stmt = $this->createMock(PDOStatement::class);
        $stmt->expects($this->once())
            ->method('execute')
            ->with($this->callback(fn(array $params): bool => $params['entity_type'] === 'auth'
                && $params['action'] === 'user.login'
                && $params['entity_id'] === '42'))
            ->willReturn(true);

        $pdo = $this->createMock(PDO::class);
        $pdo->expects($this->once())
            ->method('prepare')
            ->willReturn($stmt);

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: new DatabaseEncryption(),
        );

        $logger->logAuth(
            action: 'user.login',
            userId: 42,
            data: ['method' => '2fa'],
            ipAddress: '127.0.0.1',
            userAgent: 'Mozilla/5.0',
        );
    }

    #[Test]
    public function testLogAdminIncludesAdminUserIdInData(): void
    {
        $stmt = $this->createMock(PDOStatement::class);
        $stmt->expects($this->once())
            ->method('execute')
            ->with($this->callback(function (array $params): bool {
                $dataJson = $params['data'];
                $decoded  = json_decode($dataJson, true);
                return is_array($decoded)
                    && is_array($decoded['data'] ?? null)
                    && ($decoded['data']['admin_user_id'] ?? null) === 99;
            }))
            ->willReturn(true);

        $pdo = $this->createMock(PDO::class);
        $pdo->expects($this->once())
            ->method('prepare')
            ->willReturn($stmt);

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: new DatabaseEncryption(),
        );

        $logger->logAdmin(
            action: 'user.delete',
            adminUserId: 99,
            entityType: 'user',
            entityId: 42,
            data: ['reason' => 'violation'],
            ipAddress: '10.0.0.1',
            userAgent: 'AdminPanel/1.0',
        );
    }

    #[Test]
    public function testCustomTableNameAppearsInSqlQueries(): void
    {
        $stmt = $this->createMock(PDOStatement::class);
        $stmt->expects($this->once())
            ->method('execute')
            ->willReturn(true);

        $pdo = $this->createMock(PDO::class);
        $pdo->expects($this->once())
            ->method('prepare')
            ->with($this->stringContains('INSERT INTO custom_audit_table'))
            ->willReturn($stmt);

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: new DatabaseEncryption(),
            tableName: 'custom_audit_table',
        );

        $entry = new AuditLogEntry(
            action: 'test.action',
            entityType: 'test',
            entityId: 1,
        );

        $logger->log($entry);
    }

    #[Test]
    public function testConstructorRejectsInvalidTableName(): void
    {
        $pdo = $this->createStub(PDO::class);

        $this->expectException(StorageException::class);
        $this->expectExceptionMessage('Invalid table name');

        new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: new DatabaseEncryption(),
            tableName: 'invalid-table-name!',
        );
    }

    #[Test]
    public function testConstructorRejectsShortEncryptionKey(): void
    {
        $pdo = $this->createStub(PDO::class);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Encryption key must be at least 32 bytes');

        new AuditLogger(
            pdo: $pdo,
            encryptionKey: 'too-short-key',
        );
    }

    /**
     * Test that constructor accepts exactly 32-byte key (kills mutant #1: < to <=).
     */
    #[Test]
    public function testConstructorAcceptsExactly32ByteKey(): void
    {
        $pdo = $this->createStub(PDO::class);
        $key = str_repeat('a', 32);

        new AuditLogger(
            pdo: $pdo,
            encryptionKey: $key,
        );

        // If constructor did not throw, this passes
        $this->addToAssertionCount(1);
    }

    #[Test]
    public function testFileWritesJsonLinesFormat(): void
    {
        $stmt = $this->createMock(PDOStatement::class);
        $stmt->expects($this->exactly(2))
            ->method('execute')
            ->willReturn(true);

        $pdo = $this->createMock(PDO::class);
        $pdo->expects($this->exactly(2))
            ->method('prepare')
            ->willReturn($stmt);

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: new DatabaseEncryption(),
            logFilePath: $this->tempLogFile,
        );

        // Write two entries
        $logger->log(new AuditLogEntry(
            action: 'action1',
            entityType: 'type1',
            entityId: 1,
        ));

        $logger->log(new AuditLogEntry(
            action: 'action2',
            entityType: 'type2',
            entityId: 2,
        ));

        // Verify encrypted lines format
        $this->assertFileExists($this->tempLogFile);
        $content = file_get_contents($this->tempLogFile);
        $this->assertNotFalse($content);

        $lines = explode("\n", trim($content));
        $this->assertCount(2, $lines);

        $encryption = new AppEncryption();

        $entry1 = json_decode($encryption->decrypt($lines[0], $this->encryptionKey), true);
        $this->assertIsArray($entry1);
        $this->assertSame('action1', $entry1['action']);

        $entry2 = json_decode($encryption->decrypt($lines[1], $this->encryptionKey), true);
        $this->assertIsArray($entry2);
        $this->assertSame('action2', $entry2['action']);
    }

    #[Test]
    public function testLogThrowsStorageExceptionWhenJsonEncodeFails(): void
    {
        $pdo = $this->createStub(PDO::class);

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: new DatabaseEncryption(),
        );

        $entry = new AuditLogEntry(
            action: 'test.action',
            entityType: 'test',
            entityId: 1,
            data: ['value' => NAN],
        );

        try {
            $logger->log($entry);
            $this->fail('Expected StorageException was not thrown');
        } catch (StorageException $storageException) {
            $this->assertStringStartsWith('Failed to encode audit data as JSON: ', $storageException->getMessage());
            $this->assertGreaterThan(strlen('Failed to encode audit data as JSON: '), strlen($storageException->getMessage()));
            $this->assertSame(0, $storageException->getCode());
            $this->assertInstanceOf(JsonException::class, $storageException->getPrevious());
        }
    }

    /**
     * Test logAuth with null userId verifies entityId is '0' (kills mutants #19, #20).
     */
    #[Test]
    public function testLogAuthWithNullUserIdUsesZeroAsEntityId(): void
    {
        $capturedParams = null;

        $stmt = $this->createMock(PDOStatement::class);
        $stmt->expects($this->once())
            ->method('execute')
            ->with($this->callback(function (array $params) use (&$capturedParams): bool {
                $capturedParams = $params;
                return true;
            }))
            ->willReturn(true);

        $pdo = $this->createMock(PDO::class);
        $pdo->expects($this->once())
            ->method('prepare')
            ->willReturn($stmt);

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: new DatabaseEncryption(),
        );

        $logger->logAuth(action: 'login.failed');

        $this->assertNotNull($capturedParams);
        $this->assertSame('0', $capturedParams['entity_id']);
    }

    /**
     * Test invalid table name exception includes the identifier (kills mutants #54, #55).
     */
    #[Test]
    public function testConstructorInvalidTableNameExceptionIncludesIdentifier(): void
    {
        $pdo = $this->createStub(PDO::class);

        try {
            new AuditLogger(
                pdo: $pdo,
                encryptionKey: $this->encryptionKey,
                encryption: new DatabaseEncryption(),
                tableName: 'invalid-table!',
            );
            $this->fail('Expected StorageException was not thrown');
        } catch (StorageException $storageException) {
            $this->assertStringStartsWith('Invalid table name: ', $storageException->getMessage());
            $this->assertStringContainsString('invalid-table!', $storageException->getMessage());
        }
    }

    /**
     * Test that escapeIdentifier rejects names starting with digits (kills mutant #53: PregMatchRemoveCaret).
     */
    #[Test]
    public function testConstructorRejectsTableNameStartingWithDigit(): void
    {
        $pdo = $this->createStub(PDO::class);

        $this->expectException(StorageException::class);
        $this->expectExceptionMessage('Invalid table name: 1invalid_table');

        new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: new DatabaseEncryption(),
            tableName: '1invalid_table',
        );
    }

    /**
     * Test file log contains timestamp field (kills mutant #36: ArrayItemRemoval of timestamp).
     */
    #[Test]
    public function testFileLogContainsTimestamp(): void
    {
        $capturedParams = null;

        $stmt = $this->createMock(PDOStatement::class);
        $stmt->expects($this->once())
            ->method('execute')
            ->with($this->callback(function (array $params) use (&$capturedParams): bool {
                $capturedParams = $params;
                return true;
            }))
            ->willReturn(true);

        $pdo = $this->createMock(PDO::class);
        $pdo->expects($this->once())
            ->method('prepare')
            ->willReturn($stmt);

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: new DatabaseEncryption(),
            logFilePath: $this->tempLogFile,
        );

        $entry = new AuditLogEntry(
            action: 'user.login',
            entityType: 'user',
            entityId: 42,
            userId: 42,
            ipAddress: '127.0.0.1',
        );

        $logger->log($entry);

        $this->assertFileExists($this->tempLogFile);
        $content = file_get_contents($this->tempLogFile);
        $this->assertNotFalse($content);

        $encryption = new AppEncryption();
        $decrypted  = $encryption->decrypt(trim($content), $this->encryptionKey);
        $logEntry   = json_decode($decrypted, true);
        $this->assertIsArray($logEntry);

        // Verify all fields exist in file log (kills ArrayItemRemoval mutants)
        $this->assertArrayHasKey('timestamp', $logEntry);
        $this->assertArrayHasKey('user_id', $logEntry);
        $this->assertArrayHasKey('ip_address', $logEntry);
        $this->assertArrayHasKey('user_agent', $logEntry);
        $this->assertArrayHasKey('action', $logEntry);
        $this->assertArrayHasKey('entity_type', $logEntry);
        $this->assertArrayHasKey('entity_id', $logEntry);
        $this->assertArrayHasKey('data', $logEntry);
        $this->assertArrayHasKey('checksum', $logEntry);

        // Verify timestamp format matches captured params
        $this->assertNotNull($capturedParams);
        $this->assertSame($capturedParams['timestamp'], $logEntry['timestamp']);

        // Verify the file line ends with newline (kills mutant #38: Concat swap)
        $this->assertStringEndsWith(PHP_EOL, $content);
    }

    /**
     * Test log() captured params contain all required database fields (kills mutants #30-33).
     */
    #[Test]
    public function testLogCapturedParamsContainAllFields(): void
    {
        $capturedParams = null;

        $stmt = $this->createMock(PDOStatement::class);
        $stmt->expects($this->once())
            ->method('execute')
            ->with($this->callback(function (array $params) use (&$capturedParams): bool {
                $capturedParams = $params;
                return true;
            }))
            ->willReturn(true);

        $pdo = $this->createMock(PDO::class);
        $pdo->expects($this->once())
            ->method('prepare')
            ->willReturn($stmt);

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: new DatabaseEncryption(),
        );

        $entry = new AuditLogEntry(
            action: 'user.login',
            entityType: 'user',
            entityId: 42,
            userId: 42,
            ipAddress: '127.0.0.1',
            userAgent: 'TestBrowser/1.0',
        );

        $logger->log($entry);

        $this->assertNotNull($capturedParams);
        $this->assertArrayHasKey('timestamp', $capturedParams);
        $this->assertSame(42, $capturedParams['user_id']);
        $this->assertSame('127.0.0.1', $capturedParams['ip_address']);
        $this->assertSame('user.login', $capturedParams['action']);
        $this->assertSame('user', $capturedParams['entity_type']);
        $this->assertSame('42', $capturedParams['entity_id']);
        $this->assertArrayHasKey('checksum', $capturedParams);
    }

    #[Test]
    public function testLogCreatesLogDirectoryIfNotExists(): void
    {
        $nestedDir = sys_get_temp_dir() . '/audit-nested-' . uniqid() . '/subdir';
        $logFile   = $nestedDir . '/test.log';

        $stmt = $this->createMock(PDOStatement::class);
        $stmt->expects($this->once())
            ->method('execute')
            ->willReturn(true);

        $pdo = $this->createMock(PDO::class);
        $pdo->expects($this->once())
            ->method('prepare')
            ->willReturn($stmt);

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: new DatabaseEncryption(),
            logFilePath: $logFile,
        );

        $entry = new AuditLogEntry(
            action: 'test.action',
            entityType: 'test',
            entityId: 1,
        );

        $logger->log($entry);

        $this->assertFileExists($logFile);
        $this->assertDirectoryExists($nestedDir);

        // Cleanup
        unlink($logFile);
        rmdir($nestedDir);
        rmdir(dirname($nestedDir));
    }

    #[Test]
    public function testFileLogIsEncryptedEvenWithDatabaseEncryption(): void
    {
        $stmt = $this->createMock(PDOStatement::class);
        $stmt->expects($this->once())
            ->method('execute')
            ->willReturn(true);

        $pdo = $this->createMock(PDO::class);
        $pdo->expects($this->once())
            ->method('prepare')
            ->willReturn($stmt);

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: new DatabaseEncryption(),
            logFilePath: $this->tempLogFile,
        );

        $entry = new AuditLogEntry(
            action: 'user.login',
            entityType: 'user',
            entityId: 42,
            userId: 42,
            ipAddress: '127.0.0.1',
            userAgent: 'TestAgent/1.0',
            data: ['status' => 'success'],
        );

        $logger->log($entry);

        $this->assertFileExists($this->tempLogFile);
        $content = file_get_contents($this->tempLogFile);
        $this->assertNotFalse($content);

        // File content must NOT be plain JSON (it's encrypted)
        $this->assertNull(json_decode(trim($content), true));
        $this->assertStringNotContainsString('user.login', $content);

        // But it can be decrypted with AppEncryption
        $encryption = new AppEncryption();
        $decrypted  = $encryption->decrypt(trim($content), $this->encryptionKey);
        $logEntry   = json_decode($decrypted, true);
        $this->assertIsArray($logEntry);
        $this->assertSame('user.login', $logEntry['action']);
        $this->assertSame(42, $logEntry['user_id']);
    }

    /**
     * Test file log slashes are not escaped (verifies JSON_UNESCAPED_SLASHES, kills mutant #37).
     */
    #[Test]
    public function testFileLogPreservesSlashesAndUnicode(): void
    {
        $stmt = $this->createMock(PDOStatement::class);
        $stmt->expects($this->once())
            ->method('execute')
            ->willReturn(true);

        $pdo = $this->createMock(PDO::class);
        $pdo->expects($this->once())
            ->method('prepare')
            ->willReturn($stmt);

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: new DatabaseEncryption(),
            logFilePath: $this->tempLogFile,
        );

        $entry = new AuditLogEntry(
            action: 'user/login',
            entityType: 'user',
            entityId: 42,
            userId: 42,
            ipAddress: '127.0.0.1',
            data: ['path' => '/api/v1/users', 'name' => "\u{00E4}\u{00F6}\u{00FC}"],
        );

        $logger->log($entry);

        $this->assertFileExists($this->tempLogFile);
        $encryption = new AppEncryption();
        $content    = file_get_contents($this->tempLogFile);
        $this->assertNotFalse($content);
        $decrypted  = $encryption->decrypt(trim($content), $this->encryptionKey);

        // Slashes should NOT be escaped
        $this->assertStringContainsString('/api/v1/users', $decrypted);
        // Unicode should NOT be escaped
        $this->assertStringContainsString("\u{00E4}\u{00F6}\u{00FC}", $decrypted);
    }

    /**
     * Test writeToFile throws StorageException when JSON encoding of file log entry fails.
     * Uses Reflection because encodeData() would fail first via log(), making this path unreachable.
     *
     * @noinspection PhpUnhandledExceptionInspection - ReflectionMethod on known private method
     */
    #[Test]
    public function testWriteToFileThrowsStorageExceptionOnJsonEncodeFails(): void
    {
        $pdo = $this->createStub(PDO::class);

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: new DatabaseEncryption(),
            logFilePath: $this->tempLogFile,
        );

        $entry = new AuditLogEntry(
            action: 'test.action',
            entityType: 'test',
            entityId: 1,
            data: ['value' => NAN],
        );

        $method = new ReflectionMethod($logger, 'writeToFile');

        try {
            $method->invoke($logger, '2026-02-14 12:00:00', $entry, 'dummy-checksum');
            $this->fail('Expected StorageException was not thrown');
        } catch (StorageException $storageException) { // @phpstan-ignore catch.neverThrown (thrown inside Reflection invoke)
            $this->assertStringStartsWith('Failed to encode file log entry as JSON: ', $storageException->getMessage());
            $this->assertGreaterThan(
                strlen('Failed to encode file log entry as JSON: '),
                strlen($storageException->getMessage()),
            );
            $this->assertSame(0, $storageException->getCode());
            $this->assertInstanceOf(JsonException::class, $storageException->getPrevious());
        }
    }

    #[Test]
    public function testLogThrowsStorageExceptionWhenDataExceedsMaxSize(): void
    {
        $pdo = $this->createStub(PDO::class);

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: new DatabaseEncryption(),
        );

        $entry = new AuditLogEntry(
            action: 'test.action',
            entityType: 'test',
            entityId: 1,
            data: ['payload' => str_repeat('x', 10_000)],
        );

        try {
            $logger->log($entry);
            $this->fail('Expected StorageException was not thrown');
        } catch (StorageException $storageException) {
            $this->assertMatchesRegularExpression(
                '/Encoded audit data exceeds maximum size of 10000 bytes \(got \d+ bytes\)/',
                $storageException->getMessage(),
            );
        }
    }

    #[Test]
    public function testNewLogFileHasRestrictedPermissions(): void
    {
        $stmt = $this->createMock(PDOStatement::class);
        $stmt->expects($this->once())
            ->method('execute')
            ->willReturn(true);

        $pdo = $this->createMock(PDO::class);
        $pdo->expects($this->once())
            ->method('prepare')
            ->willReturn($stmt);

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: new DatabaseEncryption(),
            logFilePath: $this->tempLogFile,
        );

        $entry = new AuditLogEntry(
            action: 'test.action',
            entityType: 'test',
            entityId: 1,
        );

        $logger->log($entry);

        $this->assertFileExists($this->tempLogFile);
        $this->assertSame(0600, fileperms($this->tempLogFile) & 0777);
    }

    #[Test]
    public function testConstructorAcceptsValidMaxLimit(): void
    {
        $pdo = $this->createStub(PDO::class);

        new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            maxLimit: 500,
        );

        $this->addToAssertionCount(1);
    }

    /**
     * Boundary test: maxLimit=1 must be accepted (kills mutant < to <=).
     */
    #[Test]
    public function testConstructorAcceptsMaxLimitOfOne(): void
    {
        $pdo = $this->createStub(PDO::class);

        new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            maxLimit: 1,
        );

        $this->addToAssertionCount(1);
    }

    #[Test]
    public function testConstructorAcceptsNullMaxLimit(): void
    {
        $pdo = $this->createStub(PDO::class);

        new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            maxLimit: null,
        );

        $this->addToAssertionCount(1);
    }

    /**
     * Boundary test: data producing exactly 10000 bytes of JSON must be accepted (kills mutant > to >=).
     */
    #[Test]
    public function testLogAcceptsDataAtExactMaxEncodedSize(): void
    {
        $stmt = $this->createMock(PDOStatement::class);
        $stmt->expects($this->once())
            ->method('execute')
            ->willReturn(true);

        $pdo = $this->createMock(PDO::class);
        $pdo->expects($this->once())
            ->method('prepare')
            ->willReturn($stmt);

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: new DatabaseEncryption(),
        );

        // Calculate payload to produce exactly 10000 bytes of encoded JSON envelope
        // Envelope: {"meta":{"user_agent":"unknown","timestamp":"YYYY-MM-DD HH:MM:SS"},"data":{"p":"..."}}
        // Timestamp is always 19 chars in Y-m-d H:i:s format, so overhead is constant
        $overhead = strlen((string) json_encode([
            'meta' => ['user_agent' => 'unknown', 'timestamp' => '2026-02-14 12:00:00'],
            'data' => ['p' => ''],
        ]));
        $payloadSize = 10_000 - $overhead;

        $entry = new AuditLogEntry(
            action: 'test.action',
            entityType: 'test',
            entityId: 1,
            data: ['p' => str_repeat('x', $payloadSize)],
        );

        $logger->log($entry);

        $this->addToAssertionCount(1);
    }

    #[Test]
    public function testWriteToFileThrowsStorageExceptionOnMkdirFailure(): void
    {
        $root    = vfsStream::setup('root', 0000);
        $logFile = $root->url() . '/subdir/audit.log';

        $pdo = $this->createStub(PDO::class);

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: new DatabaseEncryption(),
            logFilePath: $logFile,
        );

        $entry  = new AuditLogEntry(
            action: 'test.action',
            entityType: 'test',
            entityId: 1,
        );

        $method = new ReflectionMethod($logger, 'writeToFile');

        try {
            $method->invoke($logger, '2026-02-14 12:00:00', $entry, 'dummy-checksum');
            $this->fail('Expected StorageException was not thrown');
        } catch (StorageException $storageException) { // @phpstan-ignore catch.neverThrown (thrown inside Reflection invoke)
            $this->assertStringStartsWith('Failed to create log directory: ', $storageException->getMessage());
        }
    }

    #[Test]
    public function testWriteToFileThrowsStorageExceptionOnWriteFailure(): void
    {
        $root = vfsStream::setup('root');
        vfsStream::newDirectory('logs')->at($root);
        $logFile = $root->url() . '/logs/audit.log';

        // Quota 0 makes file_put_contents return false
        vfsStream::setQuota(0);

        $pdo = $this->createStub(PDO::class);

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: new DatabaseEncryption(),
            logFilePath: $logFile,
        );

        $entry  = new AuditLogEntry(
            action: 'test.action',
            entityType: 'test',
            entityId: 1,
        );

        $method = new ReflectionMethod($logger, 'writeToFile');

        // Suppress "Only 0 of N bytes written" PHP warning from file_put_contents
        set_error_handler(static fn (): bool => true);
        try {
            $method->invoke($logger, '2026-02-14 12:00:00', $entry, 'dummy-checksum');
            $this->fail('Expected StorageException was not thrown');
        } catch (StorageException $storageException) { // @phpstan-ignore catch.neverThrown (thrown inside Reflection invoke)
            $this->assertStringStartsWith('Failed to write audit log to file: ', $storageException->getMessage());
            $this->assertStringContainsString($logFile, $storageException->getMessage());
        } finally {
            restore_error_handler();
        }
    }
}
