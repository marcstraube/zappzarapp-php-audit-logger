<?php

declare(strict_types=1);

namespace Zappzarapp\AuditLogger\Tests;

use JsonException;
use org\bovigo\vfs\vfsStream;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\AuditLogger\AuditLogEntry;
use Zappzarapp\AuditLogger\Encryption\AppEncryption;
use Zappzarapp\AuditLogger\Exception\StorageException;
use Zappzarapp\AuditLogger\FileLogWriter;

#[CoversClass(FileLogWriter::class)]
final class FileLogWriterTest extends TestCase
{
    private string $encryptionKey;

    private string $tempLogFile;

    protected function setUp(): void
    {
        $this->encryptionKey = str_repeat('a', 32);
        $this->tempLogFile   = sys_get_temp_dir() . '/audit-file-write-test-' . uniqid() . '.log';
    }

    protected function tearDown(): void
    {
        if (file_exists($this->tempLogFile)) {
            unlink($this->tempLogFile);
        }
    }

    #[Test]
    public function testWriteCreatesEncryptedLogEntryWithAllFields(): void
    {
        $writer = new FileLogWriter(
            fileEncryption: new AppEncryption(),
            encryptionKey: $this->encryptionKey,
            logFilePath: $this->tempLogFile,
        );

        $entry = new AuditLogEntry(
            action: 'test.action',
            entityType: 'test',
            entityId: 1,
            userId: 42,
            ipAddress: '127.0.0.1',
            userAgent: 'PHPUnit',
            data: ['key' => 'value'],
        );

        $writer->write('2026-02-14 12:00:00', $entry, 'dummy-checksum');

        $this->assertFileExists($this->tempLogFile);
        $content   = file_get_contents($this->tempLogFile);
        $this->assertNotFalse($content);
        $decrypted = (new AppEncryption())->decrypt(trim($content), $this->encryptionKey);
        $decoded   = json_decode($decrypted, true);
        $this->assertSame('2026-02-14 12:00:00', $decoded['timestamp']);
        $this->assertSame(42, $decoded['user_id']);
        $this->assertSame('127.0.0.1', $decoded['ip_address']);
        $this->assertSame('PHPUnit', $decoded['user_agent']);
        $this->assertSame('test.action', $decoded['action']);
        $this->assertSame('test', $decoded['entity_type']);
        $this->assertSame('1', $decoded['entity_id']);
        $this->assertSame(['key' => 'value'], $decoded['data']);
        $this->assertSame('dummy-checksum', $decoded['checksum']);
    }

    #[Test]
    public function testWriteDoesNothingWhenLogFilePathIsNull(): void
    {
        $writer = new FileLogWriter(
            fileEncryption: new AppEncryption(),
            encryptionKey: $this->encryptionKey,
            logFilePath: null,
        );

        $entry = new AuditLogEntry(
            action: 'test.action',
            entityType: 'test',
            entityId: 1,
        );

        $writer->write('2026-02-14 12:00:00', $entry, 'checksum');

        $this->assertFileDoesNotExist($this->tempLogFile);
    }

    /**
     * Test write throws StorageException when JSON encoding fails (e.g. NAN values).
     */
    #[Test]
    public function testWriteThrowsStorageExceptionOnJsonEncodeFails(): void
    {
        $writer = new FileLogWriter(
            fileEncryption: new AppEncryption(),
            encryptionKey: $this->encryptionKey,
            logFilePath: $this->tempLogFile,
        );

        $entry = new AuditLogEntry(
            action: 'test.action',
            entityType: 'test',
            entityId: 1,
            data: ['value' => NAN],
        );

        try {
            $writer->write('2026-02-14 12:00:00', $entry, 'dummy-checksum');
            $this->fail('Expected StorageException was not thrown');
        } catch (StorageException $storageException) {
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
    public function testWriteThrowsStorageExceptionOnMkdirFailure(): void
    {
        $root    = vfsStream::setup('root', 0000);
        $logFile = $root->url() . '/subdir/audit.log';

        $writer = new FileLogWriter(
            fileEncryption: new AppEncryption(),
            encryptionKey: $this->encryptionKey,
            logFilePath: $logFile,
        );

        $entry = new AuditLogEntry(
            action: 'test.action',
            entityType: 'test',
            entityId: 1,
        );

        try {
            $writer->write('2026-02-14 12:00:00', $entry, 'dummy-checksum');
            $this->fail('Expected StorageException was not thrown');
        } catch (StorageException $storageException) {
            $this->assertStringStartsWith('Failed to create log directory: ', $storageException->getMessage());
        }
    }

    #[Test]
    public function testWriteThrowsStorageExceptionOnWriteFailure(): void
    {
        $root = vfsStream::setup('root');
        vfsStream::newDirectory('logs')->at($root);
        $logFile = $root->url() . '/logs/audit.log';

        // Quota 0 makes file_put_contents return false
        vfsStream::setQuota(0);

        $writer = new FileLogWriter(
            fileEncryption: new AppEncryption(),
            encryptionKey: $this->encryptionKey,
            logFilePath: $logFile,
        );

        $entry = new AuditLogEntry(
            action: 'test.action',
            entityType: 'test',
            entityId: 1,
        );

        // Suppress "Only 0 of N bytes written" PHP warning from file_put_contents
        set_error_handler(static fn (): bool => true);
        try {
            $writer->write('2026-02-14 12:00:00', $entry, 'dummy-checksum');
            $this->fail('Expected StorageException was not thrown');
        } catch (StorageException $storageException) {
            $this->assertStringStartsWith('Failed to write audit log to file: ', $storageException->getMessage());
            $this->assertStringContainsString($logFile, $storageException->getMessage());
        } finally {
            restore_error_handler();
        }
    }

    #[Test]
    public function testWritePreservesSlashesAndUnicode(): void
    {
        $writer = new FileLogWriter(
            fileEncryption: new AppEncryption(),
            encryptionKey: $this->encryptionKey,
            logFilePath: $this->tempLogFile,
        );

        $entry = new AuditLogEntry(
            action: 'test.action',
            entityType: 'test',
            entityId: 1,
            data: ['url' => '/api/v1/users', 'name' => "\u{00E4}\u{00F6}\u{00FC}"],
        );

        $writer->write('2026-02-14 12:00:00', $entry, 'checksum');

        $content   = file_get_contents($this->tempLogFile);
        $this->assertNotFalse($content);
        $decrypted = (new AppEncryption())->decrypt(trim($content), $this->encryptionKey);

        $this->assertStringContainsString('/api/v1/users', $decrypted);
        $this->assertStringContainsString("\u{00E4}\u{00F6}\u{00FC}", $decrypted);
    }

    #[Test]
    public function testWriteAppendsMultipleEntries(): void
    {
        $writer = new FileLogWriter(
            fileEncryption: new AppEncryption(),
            encryptionKey: $this->encryptionKey,
            logFilePath: $this->tempLogFile,
        );

        $entry1 = new AuditLogEntry(action: 'first', entityType: 'test', entityId: 1);
        $entry2 = new AuditLogEntry(action: 'second', entityType: 'test', entityId: 2);

        $writer->write('2026-02-14 12:00:00', $entry1, 'checksum1');
        $writer->write('2026-02-14 12:01:00', $entry2, 'checksum2');

        $content = file_get_contents($this->tempLogFile);
        $this->assertNotFalse($content);
        $lines   = explode(PHP_EOL, trim($content));
        $this->assertCount(2, $lines);

        $encryption = new AppEncryption();
        $decoded1   = json_decode($encryption->decrypt($lines[0], $this->encryptionKey), true);
        $decoded2   = json_decode($encryption->decrypt($lines[1], $this->encryptionKey), true);
        $this->assertSame('first', $decoded1['action']);
        $this->assertSame('second', $decoded2['action']);
    }

    #[Test]
    public function testNewLogFileHasRestrictedPermissions(): void
    {
        $writer = new FileLogWriter(
            fileEncryption: new AppEncryption(),
            encryptionKey: $this->encryptionKey,
            logFilePath: $this->tempLogFile,
        );

        $entry = new AuditLogEntry(
            action: 'test.action',
            entityType: 'test',
            entityId: 1,
        );

        $writer->write('2026-02-14 12:00:00', $entry, 'checksum');

        $this->assertFileExists($this->tempLogFile);
        $this->assertSame(0600, fileperms($this->tempLogFile) & 0777);
    }
}
