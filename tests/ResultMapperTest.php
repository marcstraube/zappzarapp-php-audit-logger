<?php

declare(strict_types=1);

namespace Zappzarapp\AuditLogger\Tests;

use DateMalformedStringException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\AuditLogger\AuditLogResult;
use Zappzarapp\AuditLogger\Exception\StorageException;
use Zappzarapp\AuditLogger\ResultMapper;

#[CoversClass(ResultMapper::class)]
final class ResultMapperTest extends TestCase
{
    /**
     * @return array<string, mixed>
     */
    private function validRow(): array
    {
        return [
            'id'          => 1,
            'timestamp'   => '2026-02-15 12:00:00',
            'user_id'     => 42,
            'ip_address'  => '127.0.0.1',
            'user_agent'  => 'PHPUnit',
            'action'      => 'user.login',
            'entity_type' => 'auth',
            'entity_id'   => '42',
            'data'        => ['key' => 'value'],
            'checksum'    => 'abc123',
        ];
    }

    #[Test]
    public function testMapReturnsAuditLogResult(): void
    {
        $result = ResultMapper::map($this->validRow(), 'test context');

        $this->assertInstanceOf(AuditLogResult::class, $result);
        $this->assertSame(1, $result->id);
        $this->assertSame('2026-02-15 12:00:00', $result->timestamp->format('Y-m-d H:i:s'));
        $this->assertSame(42, $result->userId);
        $this->assertSame('127.0.0.1', $result->ipAddress);
        $this->assertSame('PHPUnit', $result->userAgent);
        $this->assertSame('user.login', $result->action);
        $this->assertSame('auth', $result->entityType);
        $this->assertSame('42', $result->entityId);
        $this->assertSame(['key' => 'value'], $result->data);
        $this->assertSame('abc123', $result->checksum);
        $this->assertNull($result->dataError);
    }

    #[Test]
    public function testMapHandlesNullUserId(): void
    {
        $row            = $this->validRow();
        $row['user_id'] = null;

        $result = ResultMapper::map($row, 'test context');

        $this->assertNull($result->userId);
    }

    #[Test]
    public function testMapCastsUserIdToInt(): void
    {
        $row            = $this->validRow();
        $row['user_id'] = '42';

        $result = ResultMapper::map($row, 'test context');

        $this->assertSame(42, $result->userId);
    }

    #[Test]
    public function testMapHandlesNullData(): void
    {
        $row         = $this->validRow();
        $row['data'] = null;

        $result = ResultMapper::map($row, 'test context');

        $this->assertNull($result->data);
    }

    #[Test]
    public function testMapHandlesMissingDataKey(): void
    {
        $row = $this->validRow();
        unset($row['data']);

        $result = ResultMapper::map($row, 'test context');

        $this->assertNull($result->data);
    }

    #[Test]
    public function testMapHandlesNonArrayData(): void
    {
        $row         = $this->validRow();
        $row['data'] = 'not-an-array';

        $result = ResultMapper::map($row, 'test context');

        $this->assertNull($result->data);
    }

    #[Test]
    public function testMapPassesDataError(): void
    {
        $result = ResultMapper::map($this->validRow(), 'test context', 'Corrupted JSON data');

        $this->assertSame('Corrupted JSON data', $result->dataError);
    }

    #[Test]
    public function testMapThrowsOnMissingRequiredFields(): void
    {
        $row = [
            'id'        => 1,
            'timestamp' => '2026-02-15 12:00:00',
        ];

        try {
            ResultMapper::map($row, 'test context');
            $this->fail('Expected StorageException was not thrown');
        } catch (StorageException $storageException) {
            $this->assertStringStartsWith('Missing required fields in test context: ', $storageException->getMessage());
            $this->assertStringContainsString('user_id', $storageException->getMessage());
            $this->assertStringContainsString('checksum', $storageException->getMessage());
        }
    }

    /**
     * Validates each required key is individually checked (kills ArrayItemRemoval mutants).
     */
    #[Test]
    public function testMapDetectsEachMissingRequiredField(): void
    {
        $requiredKeys = ['id', 'timestamp', 'user_id', 'ip_address', 'user_agent', 'action', 'entity_type', 'entity_id', 'checksum'];

        foreach ($requiredKeys as $key) {
            $row = $this->validRow();
            unset($row[$key]);

            try {
                ResultMapper::map($row, 'test context');
                $this->fail(sprintf("Expected StorageException for missing '%s'", $key));
            } catch (StorageException $storageException) {
                $this->assertStringContainsString($key, $storageException->getMessage());
            }
        }
    }

    #[Test]
    public function testMapThrowsOnInvalidTimestamp(): void
    {
        $row              = $this->validRow();
        $row['timestamp'] = 'not-a-valid-date';

        try {
            ResultMapper::map($row, 'test context');
            $this->fail('Expected StorageException was not thrown');
        } catch (StorageException $storageException) {
            $this->assertStringStartsWith('Invalid timestamp in test context: ', $storageException->getMessage());
            $this->assertSame(0, $storageException->getCode());
            $this->assertInstanceOf(DateMalformedStringException::class, $storageException->getPrevious());
            $this->assertGreaterThan(
                strlen('Invalid timestamp in test context: '),
                strlen($storageException->getMessage()),
            );
        }
    }

    #[Test]
    public function testMapUsesErrorContextInMessages(): void
    {
        $row              = $this->validRow();
        $row['timestamp'] = 'invalid';

        try {
            ResultMapper::map($row, 'file log line 7');
            $this->fail('Expected StorageException was not thrown');
        } catch (StorageException $storageException) {
            $this->assertStringContainsString('file log line 7', $storageException->getMessage());
        }
    }

    #[Test]
    public function testMapThrowsOnNonNumericId(): void
    {
        $row       = $this->validRow();
        $row['id'] = 'not-a-number';

        $this->expectException(StorageException::class);
        $this->expectExceptionMessage('Invalid type for id in test context: expected numeric');

        ResultMapper::map($row, 'test context');
    }

    #[Test]
    public function testMapThrowsOnNonNumericUserId(): void
    {
        $row            = $this->validRow();
        $row['user_id'] = 'not-a-number';

        $this->expectException(StorageException::class);
        $this->expectExceptionMessage('Invalid type for user_id in test context: expected numeric or null');

        ResultMapper::map($row, 'test context');
    }

    #[Test]
    public function testMapAcceptsStringNumericId(): void
    {
        $row       = $this->validRow();
        $row['id'] = '42';

        $result = ResultMapper::map($row, 'test context');

        $this->assertSame(42, $result->id);
    }

    #[Test]
    public function testMapAcceptsStringNumericUserId(): void
    {
        $row            = $this->validRow();
        $row['user_id'] = '42';

        $result = ResultMapper::map($row, 'test context');

        $this->assertSame(42, $result->userId);
    }
}
