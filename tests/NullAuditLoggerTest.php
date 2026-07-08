<?php

declare(strict_types=1);

namespace Zappzarapp\AuditLogger\Tests;

use DateTimeImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\AuditLogger\AuditLogEntry;
use Zappzarapp\AuditLogger\AuditLogResult;
use Zappzarapp\AuditLogger\NullAuditLogger;

#[CoversClass(NullAuditLogger::class)]
final class NullAuditLoggerTest extends TestCase
{
    private NullAuditLogger $logger;

    protected function setUp(): void
    {
        $this->logger = new NullAuditLogger();
    }

    #[Test]
    public function testLogDoesNothing(): void
    {
        $entry = new AuditLogEntry(
            action: 'user.view',
            entityType: 'user',
            entityId: 123,
            userId: 1,
            ipAddress: '127.0.0.1',
            userAgent: 'PHPUnit',
            data: ['field' => 'value']
        );

        // Should not throw exception
        $this->logger->log($entry);

        // If we get here, test passes
        $this->assertTrue(true);
    }

    #[Test]
    public function testLogAuthDoesNothing(): void
    {
        // Should not throw exception
        $this->logger->logAuth(
            action: 'auth.login',
            userId: 1,
            data: ['method' => '2fa'],
            ipAddress: '127.0.0.1',
            userAgent: 'PHPUnit'
        );

        $this->assertTrue(true);
    }

    /** @noinspection PhpRedundantOptionalArgumentInspection - explicit null documents test intent */
    #[Test]
    public function testLogAuthWithNullUserId(): void
    {
        // Should not throw exception
        $this->logger->logAuth(
            action: 'auth.failed',
            data: ['reason' => 'invalid_password'],
            ipAddress: '127.0.0.1',
            userAgent: 'PHPUnit'
        );

        $this->assertTrue(true);
    }

    #[Test]
    public function testLogAdminDoesNothing(): void
    {
        // Should not throw exception
        $this->logger->logAdmin(
            action: 'admin.user.update',
            adminUserId: 1,
            entityType: 'user',
            entityId: 123,
            data: ['field' => 'updated'],
            ipAddress: '127.0.0.1',
            userAgent: 'PHPUnit'
        );

        $this->assertTrue(true);
    }

    #[Test]
    public function testLogAdminWithStringEntityId(): void
    {
        // Should not throw exception
        $this->logger->logAdmin(
            action: 'admin.document.delete',
            adminUserId: 1,
            entityType: 'document',
            entityId: 'doc-uuid-123',
            ipAddress: '127.0.0.1',
            userAgent: 'PHPUnit'
        );

        $this->assertTrue(true);
    }

    #[Test]
    public function testGetLogsForEntityReturnsEmptyArray(): void
    {
        $result = $this->logger->getLogsForEntity(
            entityType: 'user',
            entityId: 123,
            limit: 50
        );

        $this->assertIsArray($result);
        $this->assertEmpty($result);
    }

    #[Test]
    public function testGetLogsForEntityWithStringId(): void
    {
        $result = $this->logger->getLogsForEntity(
            entityType: 'document',
            entityId: 'doc-123'
        );

        $this->assertIsArray($result);
        $this->assertEmpty($result);
    }

    #[Test]
    public function testGetLogsForUserReturnsEmptyArray(): void
    {
        $result = $this->logger->getLogsForUser(
            userId: 1,
            limit: 50
        );

        $this->assertIsArray($result);
        $this->assertEmpty($result);
    }

    #[Test]
    public function testVerifyReturnsFalse(): void
    {
        $result = new AuditLogResult(
            id: 1,
            timestamp: new DateTimeImmutable(),
            userId: 1,
            ipAddress: '127.0.0.1',
            userAgent: 'unknown',
            action: 'user.view',
            entityType: 'user',
            entityId: '123',
            data: ['field' => 'value'],
            checksum: 'abc123'
        );

        $verified = $this->logger->verify($result);

        $this->assertFalse($verified);
    }

    #[Test]
    public function testVerifyWithNullUserId(): void
    {
        $result = new AuditLogResult(
            id: 1,
            timestamp: new DateTimeImmutable(),
            userId: null,
            ipAddress: '127.0.0.1',
            userAgent: 'unknown',
            action: 'system.cleanup',
            entityType: 'system',
            entityId: '1',
            data: null,
            checksum: 'abc123'
        );

        $verified = $this->logger->verify($result);

        $this->assertFalse($verified);
    }

    #[Test]
    public function testReadFileLogReturnsEmptyArray(): void
    {
        $result = $this->logger->readFileLog();

        $this->assertIsArray($result);
        $this->assertEmpty($result);
    }

    #[Test]
    public function testMultipleOperationsDoNotInterfere(): void
    {
        // Execute multiple operations to ensure they don't affect each other
        $entry = new AuditLogEntry(
            action: 'test.action',
            entityType: 'test',
            entityId: 1
        );

        $this->logger->log($entry);
        $this->logger->logAuth('auth.test', 1);
        $this->logger->logAdmin('admin.test', 1, 'test', 1);

        $logsForEntity = $this->logger->getLogsForEntity('test', 1);
        $logsForUser   = $this->logger->getLogsForUser(1);

        $this->assertEmpty($logsForEntity);
        $this->assertEmpty($logsForUser);
    }
}
