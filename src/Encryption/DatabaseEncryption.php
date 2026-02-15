<?php

declare(strict_types=1);

namespace Zappzarapp\AuditLogger\Encryption;

/**
 * Marker class for database-level encryption
 *
 * This implementation acts as an identity function, returning input unchanged.
 * The actual encryption/decryption is performed by the database using SQL functions
 * like encrypt_text() and decrypt_text(). The AuditLogger detects this class via
 * instanceof and adjusts SQL queries accordingly.
 */
final readonly class DatabaseEncryption implements EncryptionInterface
{
    public function encrypt(string $plaintext, string $key): string
    {
        return $plaintext;
    }

    public function decrypt(string $ciphertext, string $key): string
    {
        return $ciphertext;
    }
}
