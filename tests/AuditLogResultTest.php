<?php

declare(strict_types=1);

namespace Zappzarapp\AuditLogger\Tests;

use DateTimeImmutable;
use Error;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\AuditLogger\AuditLogResult;

#[CoversClass(AuditLogResult::class)]
final class AuditLogResultTest extends TestCase
{
    #[Test]
    public function testConstructionWithAllParameters(): void
    {
        $timestamp = new DateTimeImmutable('2026-02-13 10:30:00');
        $data      = ['field' => 'value', 'nested' => ['key' => 'val']];

        $result = new AuditLogResult(
            id: 123,
            timestamp: $timestamp,
            userId: 1,
            ipAddress: '192.168.1.1',
            userAgent: 'TestAgent/1.0',
            action: 'user.update',
            entityType: 'user',
            entityId: '456',
            data: $data,
            checksum: 'abc123def456'
        );

        $this->assertSame(123, $result->id);
        $this->assertSame($timestamp, $result->timestamp);
        $this->assertSame(1, $result->userId);
        $this->assertSame('192.168.1.1', $result->ipAddress);
        $this->assertSame('TestAgent/1.0', $result->userAgent);
        $this->assertSame('user.update', $result->action);
        $this->assertSame('user', $result->entityType);
        $this->assertSame('456', $result->entityId);
        $this->assertSame($data, $result->data);
        $this->assertSame('abc123def456', $result->checksum);
    }

    #[Test]
    public function testConstructionWithNullUserId(): void
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
            checksum: 'checksum123'
        );

        $this->assertNull($result->userId);
    }

    #[Test]
    public function testConstructionWithNullData(): void
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
            data: null,
            checksum: 'checksum123'
        );

        $this->assertNull($result->data);
    }

    #[Test]
    public function testConstructionWithEmptyDataArray(): void
    {
        $result = new AuditLogResult(
            id: 1,
            timestamp: new DateTimeImmutable(),
            userId: 1,
            ipAddress: '127.0.0.1',
            userAgent: 'unknown',
            action: 'test.action',
            entityType: 'test',
            entityId: '1',
            data: [],
            checksum: 'checksum123'
        );

        $this->assertSame([], $result->data);
    }

    /**
     * @noinspection PhpReadonlyPropertyWrittenOutsideDeclarationScopeInspection - testing readonly enforcement
     * @noinspection PhpObjectFieldsAreOnlyWrittenInspection - object is used to verify readonly throws
     */
    #[Test]
    public function testReadonlyPropertiesCannotBeModified(): void
    {
        $result = new AuditLogResult(
            id: 1,
            timestamp: new DateTimeImmutable(),
            userId: 1,
            ipAddress: '127.0.0.1',
            userAgent: 'unknown',
            action: 'test.action',
            entityType: 'test',
            entityId: '1',
            data: null,
            checksum: 'checksum123'
        );

        $this->expectException(Error::class);
        $this->expectExceptionMessage('Cannot modify readonly property');

        // @phpstan-ignore property.readOnlyAssignOutOfClass
        $result->action = 'modified.action';
    }

    #[Test]
    public function testConstructionWithComplexData(): void
    {
        $complexData = [
            'before'   => ['name' => 'John', 'status' => 'active'],
            'after'    => ['name' => 'John Doe', 'status' => 'inactive'],
            'changes'  => ['name', 'status'],
            'metadata' => [
                'source'  => 'api',
                'version' => '1.0',
            ],
        ];

        $result = new AuditLogResult(
            id: 1,
            timestamp: new DateTimeImmutable(),
            userId: 1,
            ipAddress: '127.0.0.1',
            userAgent: 'unknown',
            action: 'user.update',
            entityType: 'user',
            entityId: '123',
            data: $complexData,
            checksum: 'checksum123'
        );

        $this->assertSame($complexData, $result->data);
    }

    #[Test]
    public function testTimestampIsPreserved(): void
    {
        $timestamp = new DateTimeImmutable('2026-01-01 12:00:00');

        $result = new AuditLogResult(
            id: 1,
            timestamp: $timestamp,
            userId: 1,
            ipAddress: '127.0.0.1',
            userAgent: 'unknown',
            action: 'test',
            entityType: 'test',
            entityId: '1',
            data: null,
            checksum: 'checksum123'
        );

        $this->assertSame($timestamp, $result->timestamp);
        $this->assertSame('2026-01-01 12:00:00', $result->timestamp->format('Y-m-d H:i:s'));
    }

    #[Test]
    public function testEntityIdAsString(): void
    {
        $result = new AuditLogResult(
            id: 1,
            timestamp: new DateTimeImmutable(),
            userId: 1,
            ipAddress: '127.0.0.1',
            userAgent: 'unknown',
            action: 'document.view',
            entityType: 'document',
            entityId: 'doc-uuid-12345',
            data: null,
            checksum: 'checksum123'
        );

        $this->assertSame('doc-uuid-12345', $result->entityId);
    }

    #[Test]
    public function testChecksumFormat(): void
    {
        $checksum = hash('sha256', 'test data');

        $result = new AuditLogResult(
            id: 1,
            timestamp: new DateTimeImmutable(),
            userId: 1,
            ipAddress: '127.0.0.1',
            userAgent: 'unknown',
            action: 'test',
            entityType: 'test',
            entityId: '1',
            data: null,
            checksum: $checksum
        );

        $this->assertSame(64, strlen($result->checksum)); // SHA-256 hex length
        $this->assertSame($checksum, $result->checksum);
    }

    #[Test]
    public function testDataErrorDefaultsToNull(): void
    {
        $result = new AuditLogResult(
            id: 1,
            timestamp: new DateTimeImmutable(),
            userId: 1,
            ipAddress: '127.0.0.1',
            userAgent: 'unknown',
            action: 'test',
            entityType: 'test',
            entityId: '1',
            data: null,
            checksum: 'checksum123'
        );

        $this->assertNull($result->dataError);
    }

    #[Test]
    public function testDataErrorIsPreserved(): void
    {
        $result = new AuditLogResult(
            id: 1,
            timestamp: new DateTimeImmutable(),
            userId: 1,
            ipAddress: '127.0.0.1',
            userAgent: 'unknown',
            action: 'test',
            entityType: 'test',
            entityId: '1',
            data: null,
            checksum: 'checksum123',
            dataError: 'Corrupted JSON data: Syntax error'
        );

        $this->assertSame('Corrupted JSON data: Syntax error', $result->dataError);
    }

    #[Test]
    public function testDifferentIpFormats(): void
    {
        // IPv4
        $result1 = new AuditLogResult(
            id: 1,
            timestamp: new DateTimeImmutable(),
            userId: 1,
            ipAddress: '192.168.1.1',
            userAgent: 'unknown',
            action: 'test',
            entityType: 'test',
            entityId: '1',
            data: null,
            checksum: 'checksum123'
        );
        $this->assertSame('192.168.1.1', $result1->ipAddress);

        // IPv6
        $result2 = new AuditLogResult(
            id: 2,
            timestamp: new DateTimeImmutable(),
            userId: 1,
            ipAddress: '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
            userAgent: 'unknown',
            action: 'test',
            entityType: 'test',
            entityId: '1',
            data: null,
            checksum: 'checksum456'
        );
        $this->assertSame('2001:0db8:85a3:0000:0000:8a2e:0370:7334', $result2->ipAddress);
    }
}
