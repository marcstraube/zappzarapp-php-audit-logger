<?php

declare(strict_types=1);

namespace Zappzarapp\AuditLogger\Tests;

use Error;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\AuditLogger\AuditLogEntry;

#[CoversClass(AuditLogEntry::class)]
final class AuditLogEntryTest extends TestCase
{
    #[Test]
    public function testConstructionWithAllParameters(): void
    {
        $entry = new AuditLogEntry(
            action: 'user.update',
            entityType: 'user',
            entityId: 123,
            userId: 1,
            ipAddress: '192.168.1.1',
            userAgent: 'Mozilla/5.0',
            data: ['field' => 'value', 'nested' => ['key' => 'val']]
        );

        $this->assertSame('user.update', $entry->action);
        $this->assertSame('user', $entry->entityType);
        $this->assertSame(123, $entry->entityId);
        $this->assertSame(1, $entry->userId);
        $this->assertSame('192.168.1.1', $entry->ipAddress);
        $this->assertSame('Mozilla/5.0', $entry->userAgent);
        $this->assertSame(['field' => 'value', 'nested' => ['key' => 'val']], $entry->data);
    }

    #[Test]
    public function testConstructionWithDefaults(): void
    {
        $entry = new AuditLogEntry(
            action: 'system.cleanup',
            entityType: 'system',
            entityId: 'task-123'
        );

        $this->assertSame('system.cleanup', $entry->action);
        $this->assertSame('system', $entry->entityType);
        $this->assertSame('task-123', $entry->entityId);
        $this->assertNull($entry->userId);
        $this->assertSame('unknown', $entry->ipAddress);
        $this->assertSame('unknown', $entry->userAgent);
        $this->assertSame([], $entry->data);
    }

    #[Test]
    public function testConstructionWithStringEntityId(): void
    {
        $entry = new AuditLogEntry(
            action: 'document.view',
            entityType: 'document',
            entityId: 'doc-uuid-12345'
        );

        $this->assertSame('doc-uuid-12345', $entry->entityId);
    }

    #[Test]
    public function testConstructionWithIntegerEntityId(): void
    {
        $entry = new AuditLogEntry(
            action: 'user.delete',
            entityType: 'user',
            entityId: 456
        );

        $this->assertSame(456, $entry->entityId);
    }

    #[Test]
    public function testConstructionWithNullUserId(): void
    {
        $entry = new AuditLogEntry(
            action: 'cron.job',
            entityType: 'job',
            entityId: 1
        );

        $this->assertNull($entry->userId);
    }

    #[Test]
    public function testConstructionWithEmptyData(): void
    {
        $entry = new AuditLogEntry(
            action: 'test.action',
            entityType: 'test',
            entityId: 1,
            data: []
        );

        $this->assertSame([], $entry->data);
    }

    /**
     * @noinspection PhpReadonlyPropertyWrittenOutsideDeclarationScopeInspection - testing readonly enforcement
     * @noinspection PhpObjectFieldsAreOnlyWrittenInspection - object is used to verify readonly throws
     */
    #[Test]
    public function testReadonlyPropertiesCannotBeModified(): void
    {
        $entry = new AuditLogEntry(
            action: 'test.action',
            entityType: 'test',
            entityId: 1
        );

        $this->expectException(Error::class);
        $this->expectExceptionMessage('Cannot modify readonly property');

        // @phpstan-ignore property.readOnlyAssignOutOfClass
        $entry->action = 'modified.action';
    }

    #[Test]
    public function testConstructionWithComplexData(): void
    {
        $complexData = [
            'before'   => ['name' => 'John', 'age' => 30],
            'after'    => ['name' => 'John Doe', 'age' => 31],
            'changes'  => ['name', 'age'],
            'metadata' => [
                'timestamp' => '2026-02-13T10:30:00Z',
                'source'    => 'web',
            ],
        ];

        $entry = new AuditLogEntry(
            action: 'user.update',
            entityType: 'user',
            entityId: 123,
            data: $complexData
        );

        $this->assertSame($complexData, $entry->data);
    }

    #[Test]
    public function testConstructionWithDifferentIpFormats(): void
    {
        // IPv4
        $entry1 = new AuditLogEntry(
            action: 'test',
            entityType: 'test',
            entityId: 1,
            ipAddress: '192.168.1.1'
        );
        $this->assertSame('192.168.1.1', $entry1->ipAddress);

        // IPv6
        $entry2 = new AuditLogEntry(
            action: 'test',
            entityType: 'test',
            entityId: 1,
            ipAddress: '2001:0db8:85a3:0000:0000:8a2e:0370:7334'
        );
        $this->assertSame('2001:0db8:85a3:0000:0000:8a2e:0370:7334', $entry2->ipAddress);
    }

    #[Test]
    public function testEmptyActionThrowsException(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Action must not be empty');

        new AuditLogEntry(
            action: '',
            entityType: 'test',
            entityId: 1
        );
    }

    #[Test]
    public function testEmptyEntityTypeThrowsException(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Entity type must not be empty');

        new AuditLogEntry(
            action: 'test.action',
            entityType: '',
            entityId: 1
        );
    }

    #[Test]
    public function testEmptyEntityIdThrowsException(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Entity ID must not be empty');

        new AuditLogEntry(
            action: 'test.action',
            entityType: 'test',
            entityId: ''
        );
    }

    #[Test]
    public function testActionExceedingMaxLengthThrowsException(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Action must not exceed 255 bytes');

        new AuditLogEntry(
            action: str_repeat('a', 256),
            entityType: 'test',
            entityId: 1
        );
    }

    #[Test]
    public function testEntityTypeExceedingMaxLengthThrowsException(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Entity type must not exceed 100 bytes');

        new AuditLogEntry(
            action: 'test.action',
            entityType: str_repeat('a', 101),
            entityId: 1
        );
    }

    #[Test]
    public function testEntityIdExceedingMaxLengthThrowsException(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Entity ID must not exceed 255 bytes');

        new AuditLogEntry(
            action: 'test.action',
            entityType: 'test',
            entityId: str_repeat('a', 256)
        );
    }

    #[Test]
    public function testIpAddressExceedingMaxLengthThrowsException(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('IP address must not exceed 45 bytes');

        new AuditLogEntry(
            action: 'test.action',
            entityType: 'test',
            entityId: 1,
            ipAddress: str_repeat('a', 46)
        );
    }

    #[Test]
    public function testUserAgentExceedingMaxLengthThrowsException(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('User agent must not exceed 500 bytes');

        new AuditLogEntry(
            action: 'test.action',
            entityType: 'test',
            entityId: 1,
            userAgent: str_repeat('a', 501)
        );
    }

    #[Test]
    public function testMaxLengthValuesAreAccepted(): void
    {
        $entry = new AuditLogEntry(
            action: str_repeat('a', 255),
            entityType: str_repeat('b', 100),
            entityId: str_repeat('c', 255),
            ipAddress: str_repeat('d', 45),
            userAgent: str_repeat('e', 500)
        );

        $this->assertSame(255, strlen($entry->action));
        $this->assertSame(100, strlen($entry->entityType));
        $this->assertSame(255, strlen((string) $entry->entityId));
        $this->assertSame(45, strlen($entry->ipAddress));
        $this->assertSame(500, strlen($entry->userAgent));
    }
}
