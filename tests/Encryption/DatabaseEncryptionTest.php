<?php

declare(strict_types=1);

namespace Zappzarapp\AuditLogger\Tests\Encryption;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\AuditLogger\Encryption\DatabaseEncryption;

#[CoversClass(DatabaseEncryption::class)]
final class DatabaseEncryptionTest extends TestCase
{
    private DatabaseEncryption $encryption;

    protected function setUp(): void
    {
        $this->encryption = new DatabaseEncryption();
    }

    #[Test]
    public function testEncryptReturnsPlaintextUnchanged(): void
    {
        $plaintext = 'Sensitive data';
        $key       = 'any-key';

        $result = $this->encryption->encrypt($plaintext, $key);

        $this->assertSame($plaintext, $result);
    }

    #[Test]
    public function testEncryptWithEmptyString(): void
    {
        $plaintext = '';
        $key       = 'any-key';

        $result = $this->encryption->encrypt($plaintext, $key);

        $this->assertSame('', $result);
    }

    #[Test]
    public function testEncryptWithSpecialCharacters(): void
    {
        $plaintext = "Special: \n\r\t\0 Unicode: \u{1F512}";
        $key       = 'any-key';

        $result = $this->encryption->encrypt($plaintext, $key);

        $this->assertSame($plaintext, $result);
    }

    #[Test]
    public function testDecryptReturnsCiphertextUnchanged(): void
    {
        $ciphertext = 'Any ciphertext value';
        $key        = 'any-key';

        $result = $this->encryption->decrypt($ciphertext, $key);

        $this->assertSame($ciphertext, $result);
    }

    #[Test]
    public function testDecryptWithEmptyString(): void
    {
        $ciphertext = '';
        $key        = 'any-key';

        $result = $this->encryption->decrypt($ciphertext, $key);

        $this->assertSame('', $result);
    }

    #[Test]
    public function testEncryptDecryptIsIdentityFunction(): void
    {
        $data = 'Test data for database encryption';
        $key  = 'database-key';

        // Encrypt is identity
        $encrypted = $this->encryption->encrypt($data, $key);
        $this->assertSame($data, $encrypted);

        // Decrypt is also identity
        $decrypted = $this->encryption->decrypt($encrypted, $key);
        $this->assertSame($data, $decrypted);
    }

    #[Test]
    public function testKeyIsIgnored(): void
    {
        $plaintext = 'Test data';
        $key1      = 'first-key';
        $key2      = 'second-key';

        // Different keys should produce same result (identity function)
        $result1 = $this->encryption->encrypt($plaintext, $key1);
        $result2 = $this->encryption->encrypt($plaintext, $key2);

        $this->assertSame($plaintext, $result1);
        $this->assertSame($plaintext, $result2);
    }
}
