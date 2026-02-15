<?php

declare(strict_types=1);

namespace Zappzarapp\AuditLogger\Tests;

use DateTimeImmutable;
use PDO;
use PDOStatement;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\AuditLogger\AuditLogEntry;
use Zappzarapp\AuditLogger\AuditLogger;
use Zappzarapp\AuditLogger\AuditLogResult;
use Zappzarapp\AuditLogger\Encryption\DatabaseEncryption;

#[CoversClass(AuditLogger::class)]
final class AuditLoggerVerifyTest extends TestCase
{
    private string $encryptionKey;

    private string $hmacKey;

    protected function setUp(): void
    {
        parent::setUp();
        $this->encryptionKey = 'test-encryption-key-32-characters!';
        $this->hmacKey       = hash_hkdf('sha256', $this->encryptionKey, 32, 'audit-logger-hmac');
    }

    #[Test]
    public function testVerifyReturnsTrueForValidChecksum(): void
    {
        $timestamp  = new DateTimeImmutable('2026-02-13 12:00:00');
        $action     = 'user.login';
        $entityType = 'user';
        $entityId   = '42';
        $data       = ['status' => 'success'];
        $userAgent  = 'unknown';
        $dataJson   = json_encode(['meta' => ['user_agent' => $userAgent, 'timestamp' => '2026-02-13 12:00:00'], 'data' => $data]);

        $userId    = 42;
        $ipAddress = '127.0.0.1';

        $checksum = hash_hmac(
            'sha256',
            $timestamp->format('Y-m-d H:i:s') . "\0" . $userId . "\0" . $ipAddress . "\0" . $action . "\0" . $entityType . "\0" . $entityId . "\0" . $dataJson,
            $this->hmacKey,
        );

        $result = new AuditLogResult(
            id: 1,
            timestamp: $timestamp,
            userId: $userId,
            ipAddress: $ipAddress,
            userAgent: $userAgent,
            action: $action,
            entityType: $entityType,
            entityId: $entityId,
            data: $data,
            checksum: $checksum,
        );

        $pdo    = $this->createStub(PDO::class);
        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
        );

        $this->assertTrue($logger->verify($result));
    }

    #[Test]
    public function testVerifyReturnsFalseForTamperedData(): void
    {
        $timestamp  = new DateTimeImmutable('2026-02-13 12:00:00');
        $action     = 'user.login';
        $entityType = 'user';
        $entityId   = '42';
        $data       = ['status' => 'success'];
        $userAgent  = 'unknown';
        $dataJson   = json_encode(['meta' => ['user_agent' => $userAgent, 'timestamp' => '2026-02-13 12:00:00'], 'data' => $data]);

        $userId    = 42;
        $ipAddress = '127.0.0.1';

        $checksum = hash_hmac(
            'sha256',
            $timestamp->format('Y-m-d H:i:s') . "\0" . $userId . "\0" . $ipAddress . "\0" . $action . "\0" . $entityType . "\0" . $entityId . "\0" . $dataJson,
            $this->encryptionKey,
        );

        // Tamper with data
        $tamperedData = ['status' => 'failure'];

        $result = new AuditLogResult(
            id: 1,
            timestamp: $timestamp,
            userId: $userId,
            ipAddress: $ipAddress,
            userAgent: $userAgent,
            action: $action,
            entityType: $entityType,
            entityId: $entityId,
            data: $tamperedData,
            checksum: $checksum,
        );

        $pdo    = $this->createStub(PDO::class);
        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
        );

        $this->assertFalse($logger->verify($result));
    }

    #[Test]
    public function testVerifyDetectsTamperedUserId(): void
    {
        $timestamp  = new DateTimeImmutable('2026-02-13 12:00:00');
        $data       = ['status' => 'success'];
        $dataJson   = json_encode(['meta' => ['user_agent' => 'unknown', 'timestamp' => '2026-02-13 12:00:00'], 'data' => $data]);

        $checksum = hash_hmac(
            'sha256',
            $timestamp->format('Y-m-d H:i:s') . "\0" . '42' . "\0" . '127.0.0.1' . "\0" . 'user.login' . "\0" . 'user' . "\0" . '42' . "\0" . $dataJson,
            $this->hmacKey,
        );

        $result = new AuditLogResult(
            id: 1,
            timestamp: $timestamp,
            userId: 99, // tampered from 42
            ipAddress: '127.0.0.1',
            userAgent: 'unknown',
            action: 'user.login',
            entityType: 'user',
            entityId: '42',
            data: $data,
            checksum: $checksum,
        );

        $pdo    = $this->createStub(PDO::class);
        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
        );

        $this->assertFalse($logger->verify($result));
    }

    #[Test]
    public function testVerifyDetectsTamperedIpAddress(): void
    {
        $timestamp  = new DateTimeImmutable('2026-02-13 12:00:00');
        $data       = ['status' => 'success'];
        $dataJson   = json_encode(['meta' => ['user_agent' => 'unknown', 'timestamp' => '2026-02-13 12:00:00'], 'data' => $data]);

        $checksum = hash_hmac(
            'sha256',
            $timestamp->format('Y-m-d H:i:s') . "\0" . '42' . "\0" . '127.0.0.1' . "\0" . 'user.login' . "\0" . 'user' . "\0" . '42' . "\0" . $dataJson,
            $this->hmacKey,
        );

        $result = new AuditLogResult(
            id: 1,
            timestamp: $timestamp,
            userId: 42,
            ipAddress: '192.168.1.1', // tampered
            userAgent: 'unknown',
            action: 'user.login',
            entityType: 'user',
            entityId: '42',
            data: $data,
            checksum: $checksum,
        );

        $pdo    = $this->createStub(PDO::class);
        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
        );

        $this->assertFalse($logger->verify($result));
    }

    #[Test]
    public function testVerifyDetectsTamperedAction(): void
    {
        $timestamp  = new DateTimeImmutable('2026-02-13 12:00:00');
        $data       = ['status' => 'success'];
        $dataJson   = json_encode(['meta' => ['user_agent' => 'unknown', 'timestamp' => '2026-02-13 12:00:00'], 'data' => $data]);

        $checksum = hash_hmac(
            'sha256',
            $timestamp->format('Y-m-d H:i:s') . "\0" . '42' . "\0" . '127.0.0.1' . "\0" . 'user.login' . "\0" . 'user' . "\0" . '42' . "\0" . $dataJson,
            $this->hmacKey,
        );

        $result = new AuditLogResult(
            id: 1,
            timestamp: $timestamp,
            userId: 42,
            ipAddress: '127.0.0.1',
            userAgent: 'unknown',
            action: 'user.logout', // tampered
            entityType: 'user',
            entityId: '42',
            data: $data,
            checksum: $checksum,
        );

        $pdo    = $this->createStub(PDO::class);
        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
        );

        $this->assertFalse($logger->verify($result));
    }

    #[Test]
    public function testVerifyDetectsTamperedEntityType(): void
    {
        $timestamp  = new DateTimeImmutable('2026-02-13 12:00:00');
        $data       = ['status' => 'success'];
        $dataJson   = json_encode(['meta' => ['user_agent' => 'unknown', 'timestamp' => '2026-02-13 12:00:00'], 'data' => $data]);

        $checksum = hash_hmac(
            'sha256',
            $timestamp->format('Y-m-d H:i:s') . "\0" . '42' . "\0" . '127.0.0.1' . "\0" . 'user.login' . "\0" . 'user' . "\0" . '42' . "\0" . $dataJson,
            $this->hmacKey,
        );

        $result = new AuditLogResult(
            id: 1,
            timestamp: $timestamp,
            userId: 42,
            ipAddress: '127.0.0.1',
            userAgent: 'unknown',
            action: 'user.login',
            entityType: 'admin', // tampered
            entityId: '42',
            data: $data,
            checksum: $checksum,
        );

        $pdo    = $this->createStub(PDO::class);
        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
        );

        $this->assertFalse($logger->verify($result));
    }

    #[Test]
    public function testVerifyDetectsTamperedEntityId(): void
    {
        $timestamp  = new DateTimeImmutable('2026-02-13 12:00:00');
        $data       = ['status' => 'success'];
        $dataJson   = json_encode(['meta' => ['user_agent' => 'unknown', 'timestamp' => '2026-02-13 12:00:00'], 'data' => $data]);

        $checksum = hash_hmac(
            'sha256',
            $timestamp->format('Y-m-d H:i:s') . "\0" . '42' . "\0" . '127.0.0.1' . "\0" . 'user.login' . "\0" . 'user' . "\0" . '42' . "\0" . $dataJson,
            $this->hmacKey,
        );

        $result = new AuditLogResult(
            id: 1,
            timestamp: $timestamp,
            userId: 42,
            ipAddress: '127.0.0.1',
            userAgent: 'unknown',
            action: 'user.login',
            entityType: 'user',
            entityId: '99', // tampered
            data: $data,
            checksum: $checksum,
        );

        $pdo    = $this->createStub(PDO::class);
        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
        );

        $this->assertFalse($logger->verify($result));
    }

    #[Test]
    public function testVerifyDetectsTamperedTimestamp(): void
    {
        $timestamp  = new DateTimeImmutable('2026-02-13 12:00:00');
        $data       = ['status' => 'success'];
        $dataJson   = json_encode(['meta' => ['user_agent' => 'unknown', 'timestamp' => '2026-02-13 12:00:00'], 'data' => $data]);

        $checksum = hash_hmac(
            'sha256',
            $timestamp->format('Y-m-d H:i:s') . "\0" . '42' . "\0" . '127.0.0.1' . "\0" . 'user.login' . "\0" . 'user' . "\0" . '42' . "\0" . $dataJson,
            $this->hmacKey,
        );

        $result = new AuditLogResult(
            id: 1,
            timestamp: new DateTimeImmutable('2026-02-14 12:00:00'), // tampered
            userId: 42,
            ipAddress: '127.0.0.1',
            userAgent: 'unknown',
            action: 'user.login',
            entityType: 'user',
            entityId: '42',
            data: $data,
            checksum: $checksum,
        );

        $pdo    = $this->createStub(PDO::class);
        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
        );

        $this->assertFalse($logger->verify($result));
    }

    #[Test]
    public function testVerifyWithNullUserIdDetectsTamperedToNonNull(): void
    {
        $timestamp  = new DateTimeImmutable('2026-02-13 12:00:00');
        $data       = ['status' => 'success'];
        $dataJson   = json_encode(['meta' => ['user_agent' => 'unknown', 'timestamp' => '2026-02-13 12:00:00'], 'data' => $data]);

        // Checksum computed with null userId (coalesced to '')
        $checksum = hash_hmac(
            'sha256',
            $timestamp->format('Y-m-d H:i:s') . "\0\0" . '127.0.0.1' . "\0" . 'user.login' . "\0" . 'user' . "\0" . '42' . "\0" . $dataJson,
            $this->hmacKey,
        );

        $result = new AuditLogResult(
            id: 1,
            timestamp: $timestamp,
            userId: 42, // tampered from null
            ipAddress: '127.0.0.1',
            userAgent: 'unknown',
            action: 'user.login',
            entityType: 'user',
            entityId: '42',
            data: $data,
            checksum: $checksum,
        );

        $pdo    = $this->createStub(PDO::class);
        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
        );

        $this->assertFalse($logger->verify($result));
    }

    #[Test]
    public function testVerifyWithNullUserIdValidChecksum(): void
    {
        $timestamp  = new DateTimeImmutable('2026-02-13 12:00:00');
        $data       = ['status' => 'success'];
        $dataJson   = json_encode(['meta' => ['user_agent' => 'unknown', 'timestamp' => '2026-02-13 12:00:00'], 'data' => $data]);

        $checksum = hash_hmac(
            'sha256',
            $timestamp->format('Y-m-d H:i:s') . "\0\0" . '127.0.0.1' . "\0" . 'user.login' . "\0" . 'user' . "\0" . '42' . "\0" . $dataJson,
            $this->hmacKey,
        );

        $result = new AuditLogResult(
            id: 1,
            timestamp: $timestamp,
            userId: null,
            ipAddress: '127.0.0.1',
            userAgent: 'unknown',
            action: 'user.login',
            entityType: 'user',
            entityId: '42',
            data: $data,
            checksum: $checksum,
        );

        $pdo    = $this->createStub(PDO::class);
        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
        );

        $this->assertTrue($logger->verify($result));
    }

    #[Test]
    public function testVerifyReturnsFalseWhenJsonEncodeFails(): void
    {
        $pdo    = $this->createStub(PDO::class);
        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
        );

        $result = new AuditLogResult(
            id: 1,
            timestamp: new DateTimeImmutable(),
            userId: 1,
            ipAddress: '127.0.0.1',
            userAgent: 'unknown',
            action: 'test',
            entityType: 'test',
            entityId: '1',
            data: ['value' => NAN],
            checksum: 'abc',
        );

        $this->assertFalse($logger->verify($result));
    }

    /**
     * Integration test: log() produces a checksum that verify() accepts.
     * Kills checksum concatenation mutants in log() (mutants #2-13, #30-33).
     *
     * @noinspection PhpUnhandledExceptionInspection - timestamp from captured params is always valid
     */
    #[Test]
    public function testLogAndVerifyIntegration(): void
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
            entityId: '42',
            userId: 42,
            ipAddress: '127.0.0.1',
            userAgent: 'TestBrowser/1.0',
            data: ['status' => 'success'],
        );

        $logger->log($entry);

        $this->assertNotNull($capturedParams);

        // Build AuditLogResult from captured data (DatabaseEncryption = identity)
        // $params['data'] is now envelope JSON
        $envelope = json_decode((string) $capturedParams['data'], true);

        $result = new AuditLogResult(
            id: 1,
            timestamp: new DateTimeImmutable($capturedParams['timestamp']),
            userId: $capturedParams['user_id'],
            ipAddress: $capturedParams['ip_address'],
            userAgent: $envelope['meta']['user_agent'],
            action: $capturedParams['action'],
            entityType: $capturedParams['entity_type'],
            entityId: $capturedParams['entity_id'],
            data: $envelope['data'],
            checksum: $capturedParams['checksum'],
        );

        $this->assertTrue($logger->verify($result));
    }

    /**
     * Integration test with null userId to kill the ($entry->userId ?? '') mutants (#13).
     *
     * @noinspection PhpUnhandledExceptionInspection - timestamp from captured params is always valid
     */
    #[Test]
    public function testLogAndVerifyWithNullUserId(): void
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
            action: 'system.cleanup',
            entityType: 'system',
            entityId: '1',
            userId: null,
            ipAddress: '10.0.0.1',
            userAgent: 'Cron/1.0',
            data: ['task' => 'cleanup'],
        );

        $logger->log($entry);

        $this->assertNotNull($capturedParams);
        $this->assertNull($capturedParams['user_id']);

        // $params['data'] is now envelope JSON
        $envelope = json_decode((string) $capturedParams['data'], true);

        $result = new AuditLogResult(
            id: 1,
            timestamp: new DateTimeImmutable($capturedParams['timestamp']),
            userId: $capturedParams['user_id'],
            ipAddress: $capturedParams['ip_address'],
            userAgent: $envelope['meta']['user_agent'],
            action: $capturedParams['action'],
            entityType: $capturedParams['entity_type'],
            entityId: $capturedParams['entity_id'],
            data: $envelope['data'],
            checksum: $capturedParams['checksum'],
        );

        $this->assertTrue($logger->verify($result));
    }

    /**
     * Test verify with null data produces empty string for dataJson (kills mutant #29).
     */
    #[Test]
    public function testVerifyWithNullDataUsesEmptyString(): void
    {
        $timestamp = new DateTimeImmutable('2026-02-13 12:00:00');

        // With the envelope, verify() always builds the envelope (even with null data)
        $dataJson = json_encode(['meta' => ['user_agent' => 'unknown', 'timestamp' => '2026-02-13 12:00:00'], 'data' => null]);

        $checksum = hash_hmac(
            'sha256',
            $timestamp->format('Y-m-d H:i:s') . "\0" . '42' . "\0" . '127.0.0.1' . "\0" . 'user.login' . "\0" . 'user' . "\0" . '42' . "\0" . $dataJson,
            $this->hmacKey,
        );

        $result = new AuditLogResult(
            id: 1,
            timestamp: $timestamp,
            userId: 42,
            ipAddress: '127.0.0.1',
            userAgent: 'unknown',
            action: 'user.login',
            entityType: 'user',
            entityId: '42',
            data: null,
            checksum: $checksum,
        );

        $pdo    = $this->createStub(PDO::class);
        $logger = new AuditLogger(
            pdo: $pdo,
            encryptionKey: $this->encryptionKey,
        );

        $this->assertTrue($logger->verify($result));
    }
}
