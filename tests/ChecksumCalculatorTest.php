<?php

declare(strict_types=1);

namespace Zappzarapp\AuditLogger\Tests;

use DateTimeImmutable;
use JsonException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\AuditLogger\AuditLogEntry;
use Zappzarapp\AuditLogger\AuditLogResult;
use Zappzarapp\AuditLogger\ChecksumCalculator;
use Zappzarapp\AuditLogger\Exception\StorageException;

#[CoversClass(ChecksumCalculator::class)]
final class ChecksumCalculatorTest extends TestCase
{
    private ChecksumCalculator $calculator;

    private string $hmacKey;

    protected function setUp(): void
    {
        $encryptionKey    = str_repeat('a', 32);
        $this->hmacKey    = ChecksumCalculator::deriveKey($encryptionKey);
        $this->calculator = new ChecksumCalculator($this->hmacKey);
    }

    #[Test]
    public function testDeriveKeyProducesDeterministicOutput(): void
    {
        $key1 = ChecksumCalculator::deriveKey('a]32-byte-encryption-key-here!!');
        $key2 = ChecksumCalculator::deriveKey('a]32-byte-encryption-key-here!!');

        $this->assertSame($key1, $key2);
    }

    #[Test]
    public function testEncodeDataReturnsJsonString(): void
    {
        $entry = new AuditLogEntry(
            action: 'test.action',
            entityType: 'test',
            entityId: '1',
            userAgent: 'PHPUnit',
            data: ['key' => 'value'],
        );

        $json    = $this->calculator->encodeData($entry, '2026-02-14 12:00:00');
        $decoded = json_decode($json, true);

        $this->assertIsArray($decoded);
        $this->assertSame('PHPUnit', $decoded['meta']['user_agent']);
        $this->assertSame('2026-02-14 12:00:00', $decoded['meta']['timestamp']);
        $this->assertSame(['key' => 'value'], $decoded['data']);
    }

    #[Test]
    public function testEncodeDataThrowsStorageExceptionOnJsonError(): void
    {
        $entry = new AuditLogEntry(
            action: 'test.action',
            entityType: 'test',
            entityId: '1',
            data: ['value' => NAN],
        );

        try {
            $this->calculator->encodeData($entry, '2026-02-14 12:00:00');
            $this->fail('Expected StorageException was not thrown');
        } catch (StorageException $storageException) {
            $this->assertStringStartsWith('Failed to encode audit data as JSON: ', $storageException->getMessage());
            $this->assertGreaterThan(
                strlen('Failed to encode audit data as JSON: '),
                strlen($storageException->getMessage()),
            );
            $this->assertSame(0, $storageException->getCode());
            $this->assertInstanceOf(JsonException::class, $storageException->getPrevious());
        }
    }

    #[Test]
    public function testCalculateReturnsHmacString(): void
    {
        $entry = new AuditLogEntry(
            action: 'test.action',
            entityType: 'test',
            entityId: '1',
            userId: 42,
            ipAddress: '127.0.0.1',
        );

        $dataJson = $this->calculator->encodeData($entry, '2026-02-14 12:00:00');
        $checksum = $this->calculator->calculate('2026-02-14 12:00:00', $entry, $dataJson);

        $this->assertSame(64, strlen($checksum));
        $this->assertMatchesRegularExpression('/^[a-f0-9]{64}$/', $checksum);
    }

    #[Test]
    public function testCalculateIsDeterministic(): void
    {
        $entry = new AuditLogEntry(
            action: 'test.action',
            entityType: 'test',
            entityId: '1',
        );

        $dataJson  = $this->calculator->encodeData($entry, '2026-02-14 12:00:00');
        $checksum1 = $this->calculator->calculate('2026-02-14 12:00:00', $entry, $dataJson);
        $checksum2 = $this->calculator->calculate('2026-02-14 12:00:00', $entry, $dataJson);

        $this->assertSame($checksum1, $checksum2);
    }

    #[Test]
    public function testVerifyReturnsTrueForValidChecksum(): void
    {
        $entry     = new AuditLogEntry(
            action: 'user.login',
            entityType: 'auth',
            entityId: '42',
            userId: 42,
            ipAddress: '127.0.0.1',
            userAgent: 'PHPUnit',
            data: ['key' => 'value'],
        );
        $timestamp = '2026-02-14 12:00:00';
        $dataJson  = $this->calculator->encodeData($entry, $timestamp);
        $checksum  = $this->calculator->calculate($timestamp, $entry, $dataJson);

        $result = new AuditLogResult(
            id: 1,
            timestamp: new DateTimeImmutable($timestamp),
            userId: 42,
            ipAddress: '127.0.0.1',
            userAgent: 'PHPUnit',
            action: 'user.login',
            entityType: 'auth',
            entityId: '42',
            data: ['key' => 'value'],
            checksum: $checksum,
        );

        $this->assertTrue($this->calculator->verify($result));
    }

    #[Test]
    public function testVerifyReturnsFalseForTamperedData(): void
    {
        $entry     = new AuditLogEntry(
            action: 'user.login',
            entityType: 'auth',
            entityId: '42',
            userId: 42,
            ipAddress: '127.0.0.1',
            userAgent: 'PHPUnit',
            data: ['key' => 'value'],
        );
        $timestamp = '2026-02-14 12:00:00';
        $dataJson  = $this->calculator->encodeData($entry, $timestamp);
        $checksum  = $this->calculator->calculate($timestamp, $entry, $dataJson);

        $result = new AuditLogResult(
            id: 1,
            timestamp: new DateTimeImmutable($timestamp),
            userId: 42,
            ipAddress: '127.0.0.1',
            userAgent: 'PHPUnit',
            action: 'user.login',
            entityType: 'auth',
            entityId: '42',
            data: ['key' => 'TAMPERED'],
            checksum: $checksum,
        );

        $this->assertFalse($this->calculator->verify($result));
    }

    #[Test]
    public function testVerifyWithEmptyData(): void
    {
        $entry     = new AuditLogEntry(
            action: 'user.login',
            entityType: 'auth',
            entityId: '42',
            userId: 42,
            ipAddress: '127.0.0.1',
            userAgent: 'PHPUnit',
        );
        $timestamp = '2026-02-14 12:00:00';
        $dataJson  = $this->calculator->encodeData($entry, $timestamp);
        $checksum  = $this->calculator->calculate($timestamp, $entry, $dataJson);

        $result = new AuditLogResult(
            id: 1,
            timestamp: new DateTimeImmutable($timestamp),
            userId: 42,
            ipAddress: '127.0.0.1',
            userAgent: 'PHPUnit',
            action: 'user.login',
            entityType: 'auth',
            entityId: '42',
            data: [],
            checksum: $checksum,
        );

        $this->assertTrue($this->calculator->verify($result));
    }

    #[Test]
    public function testVerifyWithNullUserId(): void
    {
        $entry     = new AuditLogEntry(
            action: 'login.failed',
            entityType: 'auth',
            entityId: '0',
            ipAddress: '127.0.0.1',
            userAgent: 'PHPUnit',
        );
        $timestamp = '2026-02-14 12:00:00';
        $dataJson  = $this->calculator->encodeData($entry, $timestamp);
        $checksum  = $this->calculator->calculate($timestamp, $entry, $dataJson);

        $result = new AuditLogResult(
            id: 1,
            timestamp: new DateTimeImmutable($timestamp),
            userId: null,
            ipAddress: '127.0.0.1',
            userAgent: 'PHPUnit',
            action: 'login.failed',
            entityType: 'auth',
            entityId: '0',
            data: [],
            checksum: $checksum,
        );

        $this->assertTrue($this->calculator->verify($result));
    }

    #[Test]
    public function testVerifyDetectsTamperedAction(): void
    {
        $entry     = $this->createTestEntry();
        $timestamp = '2026-02-14 12:00:00';
        $dataJson  = $this->calculator->encodeData($entry, $timestamp);
        $checksum  = $this->calculator->calculate($timestamp, $entry, $dataJson);

        $result = $this->createTestResult($timestamp, $checksum, action: 'TAMPERED');

        $this->assertFalse($this->calculator->verify($result));
    }

    #[Test]
    public function testVerifyDetectsTamperedEntityType(): void
    {
        $entry     = $this->createTestEntry();
        $timestamp = '2026-02-14 12:00:00';
        $dataJson  = $this->calculator->encodeData($entry, $timestamp);
        $checksum  = $this->calculator->calculate($timestamp, $entry, $dataJson);

        $result = $this->createTestResult($timestamp, $checksum, entityType: 'TAMPERED');

        $this->assertFalse($this->calculator->verify($result));
    }

    #[Test]
    public function testVerifyDetectsTamperedEntityId(): void
    {
        $entry     = $this->createTestEntry();
        $timestamp = '2026-02-14 12:00:00';
        $dataJson  = $this->calculator->encodeData($entry, $timestamp);
        $checksum  = $this->calculator->calculate($timestamp, $entry, $dataJson);

        $result = $this->createTestResult($timestamp, $checksum, entityId: '999');

        $this->assertFalse($this->calculator->verify($result));
    }

    #[Test]
    public function testVerifyDetectsTamperedIpAddress(): void
    {
        $entry     = $this->createTestEntry();
        $timestamp = '2026-02-14 12:00:00';
        $dataJson  = $this->calculator->encodeData($entry, $timestamp);
        $checksum  = $this->calculator->calculate($timestamp, $entry, $dataJson);

        $result = $this->createTestResult($timestamp, $checksum, ipAddress: '10.0.0.1');

        $this->assertFalse($this->calculator->verify($result));
    }

    #[Test]
    public function testVerifyDetectsTamperedUserAgent(): void
    {
        $entry     = $this->createTestEntry();
        $timestamp = '2026-02-14 12:00:00';
        $dataJson  = $this->calculator->encodeData($entry, $timestamp);
        $checksum  = $this->calculator->calculate($timestamp, $entry, $dataJson);

        $result = $this->createTestResult($timestamp, $checksum, userAgent: 'TAMPERED');

        $this->assertFalse($this->calculator->verify($result));
    }

    #[Test]
    public function testVerifyDetectsTamperedTimestamp(): void
    {
        $entry     = $this->createTestEntry();
        $timestamp = '2026-02-14 12:00:00';
        $dataJson  = $this->calculator->encodeData($entry, $timestamp);
        $checksum  = $this->calculator->calculate($timestamp, $entry, $dataJson);

        $result = $this->createTestResult('2026-02-14 13:00:00', $checksum);

        $this->assertFalse($this->calculator->verify($result));
    }

    #[Test]
    public function testVerifyDetectsTamperedUserId(): void
    {
        $entry     = $this->createTestEntry();
        $timestamp = '2026-02-14 12:00:00';
        $dataJson  = $this->calculator->encodeData($entry, $timestamp);
        $checksum  = $this->calculator->calculate($timestamp, $entry, $dataJson);

        $result = $this->createTestResult($timestamp, $checksum, userId: 999);

        $this->assertFalse($this->calculator->verify($result));
    }

    #[Test]
    public function testVerifyDetectsNullUserIdTamperedToNonNull(): void
    {
        $entry     = new AuditLogEntry(
            action: 'login.failed',
            entityType: 'auth',
            entityId: '0',
            ipAddress: '127.0.0.1',
            userAgent: 'PHPUnit',
        );
        $timestamp = '2026-02-14 12:00:00';
        $dataJson  = $this->calculator->encodeData($entry, $timestamp);
        $checksum  = $this->calculator->calculate($timestamp, $entry, $dataJson);

        $result = new AuditLogResult(
            id: 1,
            timestamp: new DateTimeImmutable($timestamp),
            userId: 42,
            ipAddress: '127.0.0.1',
            userAgent: 'PHPUnit',
            action: 'login.failed',
            entityType: 'auth',
            entityId: '0',
            data: [],
            checksum: $checksum,
        );

        $this->assertFalse($this->calculator->verify($result));
    }

    #[Test]
    public function testVerifyDetectsTamperedChecksum(): void
    {
        $this->createTestEntry();
        $timestamp = '2026-02-14 12:00:00';

        $result = $this->createTestResult($timestamp, 'invalid-checksum');

        $this->assertFalse($this->calculator->verify($result));
    }

    #[Test]
    public function testEncodeDataWithNullData(): void
    {
        $entry = new AuditLogEntry(
            action: 'test.action',
            entityType: 'test',
            entityId: '1',
            data: [],
        );

        $json    = $this->calculator->encodeData($entry, '2026-02-14 12:00:00');
        $decoded = json_decode($json, true);

        $this->assertSame([], $decoded['data']);
    }

    /**
     * Golden-value test: verifies the exact checksum for a known input.
     * Kills all ConcatOperandRemoval/Concat mutants in buildChecksumInput(),
     * since any structural change to the concatenation produces a different HMAC.
     */
    #[Test]
    public function testCalculateProducesExpectedGoldenChecksum(): void
    {
        // Use a fixed key to produce a deterministic checksum
        $hmacKey    = hash_hkdf('sha256', str_repeat('k', 32), 32, 'audit-logger-hmac');
        $calculator = new ChecksumCalculator($hmacKey);

        $entry     = new AuditLogEntry(
            action: 'user.login',
            entityType: 'auth',
            entityId: '42',
            userId: 7,
            ipAddress: '10.0.0.1',
            userAgent: 'TestAgent',
            data: ['role' => 'admin'],
        );
        $timestamp = '2026-01-01 00:00:00';
        $dataJson  = $calculator->encodeData($entry, $timestamp);

        // Pre-computed golden value — any mutation to buildChecksumInput changes this
        $expected = hash_hmac(
            'sha256',
            "2026-01-01 00:00:00\x007\x0010.0.0.1\x00user.login\x00auth\x0042\x00" . $dataJson,
            $hmacKey,
        );

        $this->assertSame($expected, $calculator->calculate($timestamp, $entry, $dataJson));
    }

    /**
     * Kills DecrementInteger/IncrementInteger mutants on deriveKey() key length parameter.
     */
    #[Test]
    public function testDeriveKeyProduces32ByteKey(): void
    {
        $key = ChecksumCalculator::deriveKey(str_repeat('a', 32));

        $this->assertSame(32, strlen($key));
    }

    #[Test]
    public function testTimestampFormatConstant(): void
    {
        $this->assertSame('Y-m-d H:i:s', ChecksumCalculator::TIMESTAMP_FORMAT);
    }

    private function createTestEntry(): AuditLogEntry
    {
        return new AuditLogEntry(
            action: 'user.login',
            entityType: 'auth',
            entityId: '42',
            userId: 42,
            ipAddress: '127.0.0.1',
            userAgent: 'PHPUnit',
            data: ['key' => 'value'],
        );
    }

    private function createTestResult(
        string $timestamp,
        string $checksum,
        ?int $userId = 42,
        string $ipAddress = '127.0.0.1',
        string $userAgent = 'PHPUnit',
        string $action = 'user.login',
        string $entityType = 'auth',
        string $entityId = '42',
    ): AuditLogResult {
        return new AuditLogResult(
            id: 1,
            timestamp: new DateTimeImmutable($timestamp),
            userId: $userId,
            ipAddress: $ipAddress,
            userAgent: $userAgent,
            action: $action,
            entityType: $entityType,
            entityId: $entityId,
            data: ['key' => 'value'],
            checksum: $checksum,
        );
    }
}
