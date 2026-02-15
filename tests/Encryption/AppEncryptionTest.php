<?php

declare(strict_types=1);

namespace Zappzarapp\AuditLogger\Tests\Encryption;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Random\RandomException;
use Zappzarapp\AuditLogger\Encryption\AppEncryption;
use Zappzarapp\AuditLogger\Exception\EncryptionException;

#[CoversClass(AppEncryption::class)]
final class AppEncryptionTest extends TestCase
{
    private AppEncryption $encryption;

    protected function setUp(): void
    {
        $this->encryption = new AppEncryption();
    }

    /** @throws RandomException */
    #[Test]
    public function testEncryptDecryptRoundtrip(): void
    {
        $plaintext = 'Sensitive audit log data';
        $key       = random_bytes(32);

        $ciphertext = $this->encryption->encrypt($plaintext, $key);
        $decrypted  = $this->encryption->decrypt($ciphertext, $key);

        $this->assertSame($plaintext, $decrypted);
    }

    /** @throws RandomException */
    #[Test]
    public function testEncryptDecryptWithEmptyString(): void
    {
        $plaintext = '';
        $key       = random_bytes(32);

        $ciphertext = $this->encryption->encrypt($plaintext, $key);
        $decrypted  = $this->encryption->decrypt($ciphertext, $key);

        $this->assertSame($plaintext, $decrypted);
    }

    /** @throws RandomException */
    #[Test]
    public function testEncryptDecryptWithSpecialCharacters(): void
    {
        $plaintext = "Special: \n\r\t\0 Unicode: \u{1F512} JSON: {\"key\":\"value\"}";
        $key       = random_bytes(32);

        $ciphertext = $this->encryption->encrypt($plaintext, $key);
        $decrypted  = $this->encryption->decrypt($ciphertext, $key);

        $this->assertSame($plaintext, $decrypted);
    }

    /** @throws RandomException */
    #[Test]
    public function testDifferentKeyLengthsWork(): void
    {
        $plaintext = 'Test data';

        // 128-bit key (16 bytes)
        $key16        = random_bytes(16);
        $ciphertext16 = $this->encryption->encrypt($plaintext, $key16);
        $this->assertSame($plaintext, $this->encryption->decrypt($ciphertext16, $key16));

        // 256-bit key (32 bytes)
        $key32        = random_bytes(32);
        $ciphertext32 = $this->encryption->encrypt($plaintext, $key32);
        $this->assertSame($plaintext, $this->encryption->decrypt($ciphertext32, $key32));
    }

    /** @throws RandomException */
    #[Test]
    public function testDecryptWithWrongKeyThrowsException(): void
    {
        $plaintext  = 'Secret data';
        $correctKey = random_bytes(32);
        $wrongKey   = random_bytes(32);

        $ciphertext = $this->encryption->encrypt($plaintext, $correctKey);

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Failed to decrypt data');

        $this->encryption->decrypt($ciphertext, $wrongKey);
    }

    /** @throws RandomException */
    #[Test]
    public function testDecryptWithInvalidBase64ThrowsException(): void
    {
        $invalidCiphertext = 'Not valid base64!@#$%';
        $key               = random_bytes(32);

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Failed to decode base64 ciphertext');

        $this->encryption->decrypt($invalidCiphertext, $key);
    }

    /** @throws RandomException */
    #[Test]
    public function testDecryptWithTruncatedCiphertextThrowsException(): void
    {
        $plaintext = 'Test';
        $key       = random_bytes(32);

        $ciphertext = $this->encryption->encrypt($plaintext, $key);
        $decoded    = base64_decode($ciphertext);

        // Truncate to less than IV (12) + Tag (16) = 28 bytes
        $truncated = base64_encode(substr($decoded, 0, 20));

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Ciphertext is too short to contain IV and tag');

        $this->encryption->decrypt($truncated, $key);
    }

    /** @throws RandomException */
    #[Test]
    public function testDecryptWithEmptyStringThrowsException(): void
    {
        $key = random_bytes(32);

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Ciphertext is too short to contain IV and tag');

        $this->encryption->decrypt('', $key);
    }

    /** @throws RandomException */
    #[Test]
    public function testEncryptProducesDifferentOutputEachTime(): void
    {
        $plaintext = 'Same plaintext';
        $key       = random_bytes(32);

        $ciphertext1 = $this->encryption->encrypt($plaintext, $key);
        $ciphertext2 = $this->encryption->encrypt($plaintext, $key);

        // Different ciphertexts due to random IV
        $this->assertNotSame($ciphertext1, $ciphertext2);

        // But both decrypt to same plaintext
        $this->assertSame($plaintext, $this->encryption->decrypt($ciphertext1, $key));
        $this->assertSame($plaintext, $this->encryption->decrypt($ciphertext2, $key));
    }

    /** @throws RandomException */
    #[Test]
    public function testEncryptReturnsBase64EncodedString(): void
    {
        $plaintext = 'Test data';
        $key       = random_bytes(32);

        $ciphertext = $this->encryption->encrypt($plaintext, $key);

        // Should be valid base64
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9+\/]+=*$/', $ciphertext);
        $this->assertNotFalse(base64_decode($ciphertext, true));
    }

    #[Test]
    public function testHkdfIsolatesKeyMaterial(): void
    {
        $plaintext = 'Sensitive data for HKDF isolation test';

        $keyA = str_repeat('A', 32);
        $keyB = str_repeat('B', 32);

        $ciphertextA = $this->encryption->encrypt($plaintext, $keyA);
        $ciphertextB = $this->encryption->encrypt($plaintext, $keyB);

        // Each key can decrypt its own ciphertext
        $this->assertSame($plaintext, $this->encryption->decrypt($ciphertextA, $keyA));
        $this->assertSame($plaintext, $this->encryption->decrypt($ciphertextB, $keyB));

        // Cross-decryption fails
        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Failed to decrypt data');

        $this->encryption->decrypt($ciphertextA, $keyB);
    }

    /** @throws RandomException */
    #[Test]
    public function testDecryptWithManipulatedCiphertextThrowsException(): void
    {
        $plaintext = 'Original data';
        $key       = random_bytes(32);

        $ciphertext = $this->encryption->encrypt($plaintext, $key);
        $decoded    = base64_decode($ciphertext);

        // Flip a bit in the ciphertext portion (after IV and tag)
        $manipulated       = $decoded;
        $manipulated[30]   = chr(ord($manipulated[30]) ^ 1);
        $manipulatedBase64 = base64_encode($manipulated);

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Failed to decrypt data');

        $this->encryption->decrypt($manipulatedBase64, $key);
    }
}
