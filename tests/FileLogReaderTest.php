<?php

declare(strict_types=1);

namespace Zappzarapp\AuditLogger\Tests;

use JsonException;
use PDO;
use PDOStatement;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\AuditLogger\AuditLogEntry;
use Zappzarapp\AuditLogger\AuditLogger;
use Zappzarapp\AuditLogger\AuditLogResult;
use Zappzarapp\AuditLogger\Encryption\AppEncryption;
use Zappzarapp\AuditLogger\Encryption\DatabaseEncryption;
use Zappzarapp\AuditLogger\Exception\EncryptionException;
use Zappzarapp\AuditLogger\Exception\StorageException;
use Zappzarapp\AuditLogger\FileLogReader;

#[CoversClass(FileLogReader::class)]
#[CoversClass(AuditLogger::class)]
final class FileLogReaderTest extends TestCase
{
    private string $encryptionKey;

    private string $tempLogFile;

    protected function setUp(): void
    {
        parent::setUp();
        $this->encryptionKey = 'test-encryption-key-32-characters!';
        $this->tempLogFile   = sys_get_temp_dir() . '/audit-file-read-test-' . uniqid() . '.log';
    }

    protected function tearDown(): void
    {
        if (file_exists($this->tempLogFile)) {
            unlink($this->tempLogFile);
        }

        parent::tearDown();
    }

    #[Test]
    public function testReadFileLogReturnsEmptyArrayWhenLogFilePathIsNull(): void
    {
        $reader = new FileLogReader(
            fileEncryption: new AppEncryption(),
            encryptionKey: $this->encryptionKey,
        );

        $this->assertSame([], $reader->readFileLog());
    }

    #[Test]
    public function testReadFileLogReturnsEmptyArrayWhenFileDoesNotExist(): void
    {
        $reader = new FileLogReader(
            fileEncryption: new AppEncryption(),
            encryptionKey: $this->encryptionKey,
            logFilePath: '/tmp/nonexistent-' . uniqid() . '.log',
        );

        $this->assertSame([], $reader->readFileLog());
    }

    #[Test]
    public function testReadFileLogReturnsEmptyArrayForEmptyFile(): void
    {
        file_put_contents($this->tempLogFile, '');

        $reader = new FileLogReader(
            fileEncryption: new AppEncryption(),
            encryptionKey: $this->encryptionKey,
            logFilePath: $this->tempLogFile,
        );

        $this->assertSame([], $reader->readFileLog());
    }

    #[Test]
    public function testReadFileLogSingleEntryRoundtrip(): void
    {
        $stmt = $this->createStub(PDOStatement::class);
        $stmt->method('execute')->willReturn(true);

        $pdo = $this->createStub(PDO::class);
        $pdo->method('prepare')->willReturn($stmt);

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: new DatabaseEncryption(),
            logFilePath: $this->tempLogFile,
        );

        $logger->log(new AuditLogEntry(
            action: 'user.login',
            entityType: 'user',
            entityId: 42,
            userId: 7,
            ipAddress: '192.168.1.1',
            userAgent: 'TestBrowser/1.0',
            data: ['method' => '2fa'],
        ));

        $results = $logger->readFileLog();

        $this->assertCount(1, $results);
        $this->assertInstanceOf(AuditLogResult::class, $results[0]);
        $this->assertSame(1, $results[0]->id);
        $this->assertSame(7, $results[0]->userId);
        $this->assertSame('192.168.1.1', $results[0]->ipAddress);
        $this->assertSame('TestBrowser/1.0', $results[0]->userAgent);
        $this->assertSame('user.login', $results[0]->action);
        $this->assertSame('user', $results[0]->entityType);
        $this->assertSame('42', $results[0]->entityId);
        $this->assertSame(['method' => '2fa'], $results[0]->data);
        $this->assertNotEmpty($results[0]->checksum);
        $this->assertNull($results[0]->dataError);
    }

    #[Test]
    public function testReadFileLogMultipleEntriesPreservesOrder(): void
    {
        $stmt = $this->createStub(PDOStatement::class);
        $stmt->method('execute')->willReturn(true);

        $pdo = $this->createStub(PDO::class);
        $pdo->method('prepare')->willReturn($stmt);

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: new DatabaseEncryption(),
            logFilePath: $this->tempLogFile,
        );

        $logger->log(new AuditLogEntry(
            action: 'action.first',
            entityType: 'test',
            entityId: 1,
        ));

        $logger->log(new AuditLogEntry(
            action: 'action.second',
            entityType: 'test',
            entityId: 2,
        ));

        $logger->log(new AuditLogEntry(
            action: 'action.third',
            entityType: 'test',
            entityId: 3,
        ));

        $results = $logger->readFileLog();

        $this->assertCount(3, $results);
        $this->assertSame(1, $results[0]->id);
        $this->assertSame('action.first', $results[0]->action);
        $this->assertSame(2, $results[1]->id);
        $this->assertSame('action.second', $results[1]->action);
        $this->assertSame(3, $results[2]->id);
        $this->assertSame('action.third', $results[2]->action);
    }

    #[Test]
    public function testReadFileLogResultsCanBeVerified(): void
    {
        $stmt = $this->createStub(PDOStatement::class);
        $stmt->method('execute')->willReturn(true);

        $pdo = $this->createStub(PDO::class);
        $pdo->method('prepare')->willReturn($stmt);

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: new DatabaseEncryption(),
            logFilePath: $this->tempLogFile,
        );

        $logger->log(new AuditLogEntry(
            action: 'user.update',
            entityType: 'user',
            entityId: 99,
            userId: 1,
            ipAddress: '10.0.0.1',
            userAgent: 'IntegrationTest/1.0',
            data: ['field' => 'email'],
        ));

        $results = $logger->readFileLog();

        $this->assertCount(1, $results);
        $this->assertTrue($logger->verify($results[0]));
    }

    #[Test]
    public function testReadFileLogThrowsStorageExceptionOnCorruptJson(): void
    {
        $encryption = new AppEncryption();
        $encrypted  = $encryption->encrypt('not-valid-json{', $this->encryptionKey);
        file_put_contents($this->tempLogFile, $encrypted . PHP_EOL);

        $reader = new FileLogReader(
            fileEncryption: new AppEncryption(),
            encryptionKey: $this->encryptionKey,
            logFilePath: $this->tempLogFile,
        );

        try {
            $reader->readFileLog();
            $this->fail('Expected StorageException was not thrown');
        } catch (StorageException $storageException) {
            $this->assertStringStartsWith('Corrupted JSON in file log line 1: ', $storageException->getMessage());
            $this->assertGreaterThan(
                strlen('Corrupted JSON in file log line 1: '),
                strlen($storageException->getMessage()),
            );
            $this->assertSame(0, $storageException->getCode());
            $this->assertInstanceOf(JsonException::class, $storageException->getPrevious());
        }
    }

    #[Test]
    public function testReadFileLogThrowsEncryptionExceptionOnWrongKey(): void
    {
        $encryption = new AppEncryption();
        $encrypted  = $encryption->encrypt('{"test": true}', 'different-key-that-is-32-chars!!');
        file_put_contents($this->tempLogFile, $encrypted . PHP_EOL);

        $reader = new FileLogReader(
            fileEncryption: new AppEncryption(),
            encryptionKey: $this->encryptionKey,
            logFilePath: $this->tempLogFile,
        );

        $this->expectException(EncryptionException::class);

        $reader->readFileLog();
    }

    #[Test]
    public function testReadFileLogThrowsStorageExceptionOnMissingRequiredFields(): void
    {
        $encryption = new AppEncryption();
        $encrypted  = $encryption->encrypt((string) json_encode(['timestamp' => '2026-02-15 12:00:00']), $this->encryptionKey);
        file_put_contents($this->tempLogFile, $encrypted . PHP_EOL);

        $reader = new FileLogReader(
            fileEncryption: new AppEncryption(),
            encryptionKey: $this->encryptionKey,
            logFilePath: $this->tempLogFile,
        );

        try {
            $reader->readFileLog();
            $this->fail('Expected StorageException was not thrown');
        } catch (StorageException $storageException) {
            $this->assertStringStartsWith('Missing required fields in file log line 1: ', $storageException->getMessage());
            $this->assertStringContainsString('checksum', $storageException->getMessage());
            $this->assertGreaterThan(
                strlen('Missing required fields in file log line 1: '),
                strlen($storageException->getMessage()),
            );
        }
    }

    /**
     * Test that each required field in file log is individually validated (kills ArrayItemRemoval mutants).
     */
    #[Test]
    public function testReadFileLogDetectsMissingTimestamp(): void
    {
        $encryption = new AppEncryption();
        $entry      = [
            // 'timestamp' intentionally missing
            'user_id'     => 1,
            'ip_address'  => '127.0.0.1',
            'user_agent'  => 'test',
            'action'      => 'test',
            'entity_type' => 'test',
            'entity_id'   => '1',
            'data'        => null,
            'checksum'    => 'abc',
        ];
        $encrypted  = $encryption->encrypt((string) json_encode($entry), $this->encryptionKey);
        file_put_contents($this->tempLogFile, $encrypted . PHP_EOL);

        $reader = new FileLogReader(
            fileEncryption: new AppEncryption(),
            encryptionKey: $this->encryptionKey,
            logFilePath: $this->tempLogFile,
        );

        try {
            $reader->readFileLog();
            $this->fail('Expected StorageException was not thrown');
        } catch (StorageException $storageException) {
            $this->assertStringContainsString('timestamp', $storageException->getMessage());
        }
    }

    /**
     * Test that readFileLog casts user_id to int (kills CastInt mutant).
     */
    #[Test]
    public function testReadFileLogCastsUserIdToInt(): void
    {
        $encryption = new AppEncryption();
        $hmacKey    = hash_hkdf('sha256', $this->encryptionKey, 32, 'audit-logger-hmac');

        $timestamp  = '2026-02-15 12:00:00';
        $dataJson   = json_encode(['meta' => ['user_agent' => 'test', 'timestamp' => $timestamp], 'data' => null]);
        $checksum   = hash_hmac(
            'sha256',
            $timestamp . "\0" . '42' . "\0" . '127.0.0.1' . "\0" . 'test' . "\0" . 'test' . "\0" . '1' . "\0" . $dataJson,
            $hmacKey,
        );

        $entry     = [
            'timestamp'   => $timestamp,
            'user_id'     => 42,
            'ip_address'  => '127.0.0.1',
            'user_agent'  => 'test',
            'action'      => 'test',
            'entity_type' => 'test',
            'entity_id'   => '1',
            'data'        => null,
            'checksum'    => $checksum,
        ];
        $encrypted = $encryption->encrypt((string) json_encode($entry), $this->encryptionKey);
        file_put_contents($this->tempLogFile, $encrypted . PHP_EOL);

        $reader = new FileLogReader(
            fileEncryption: new AppEncryption(),
            encryptionKey: $this->encryptionKey,
            logFilePath: $this->tempLogFile,
        );

        $results = $reader->readFileLog();

        $this->assertCount(1, $results);
        $this->assertIsInt($results[0]->userId);
        $this->assertSame(42, $results[0]->userId);
    }

    #[Test]
    public function testReadFileLogWithDatabaseEncryptionStillUsesAppEncryption(): void
    {
        $stmt = $this->createStub(PDOStatement::class);
        $stmt->method('execute')->willReturn(true);

        $pdo = $this->createStub(PDO::class);
        $pdo->method('prepare')->willReturn($stmt);

        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
            encryption: new DatabaseEncryption(),
            logFilePath: $this->tempLogFile,
        );

        $logger->log(new AuditLogEntry(
            action: 'db.encryption.test',
            entityType: 'test',
            entityId: 1,
            data: ['strategy' => 'database'],
        ));

        // Verify the file can be read back — proves AppEncryption was used for file
        $results = $logger->readFileLog();

        $this->assertCount(1, $results);
        $this->assertSame('db.encryption.test', $results[0]->action);

        // Also verify the file content is AppEncryption-encrypted
        $appEncryption = new AppEncryption();
        $content       = file_get_contents($this->tempLogFile);
        $this->assertNotFalse($content);
        $decrypted     = $appEncryption->decrypt(trim($content), $this->encryptionKey);
        $this->assertJson($decrypted);
    }

    #[Test]
    public function testReadFileLogThrowsStorageExceptionWhenFileTooLarge(): void
    {
        // Create a file exceeding 10 MB
        file_put_contents($this->tempLogFile, str_repeat('x', 10_485_761));

        $reader = new FileLogReader(
            fileEncryption: new AppEncryption(),
            encryptionKey: $this->encryptionKey,
            logFilePath: $this->tempLogFile,
        );

        $this->expectException(StorageException::class);
        $this->expectExceptionMessage('File log exceeds maximum size of 10485760 bytes');

        $reader->readFileLog();
    }

    /**
     * Boundary test: file at exactly MAX_FILE_LOG_SIZE must be accepted (kills > to >= mutant).
     */
    #[Test]
    public function testReadFileLogAcceptsFileAtExactMaxSize(): void
    {
        // Create file at exactly 10 MB
        file_put_contents($this->tempLogFile, str_repeat('x', 10_485_760));

        $reader = new FileLogReader(
            fileEncryption: new AppEncryption(),
            encryptionKey: $this->encryptionKey,
            logFilePath: $this->tempLogFile,
        );

        // Size check passes — decryption will fail on garbage data, but that's expected
        try {
            $reader->readFileLog();
        } catch (StorageException | EncryptionException $exception) {
            // Must NOT be the size-limit error
            $this->assertStringNotContainsString('exceeds maximum size', $exception->getMessage());
        }
    }
}
