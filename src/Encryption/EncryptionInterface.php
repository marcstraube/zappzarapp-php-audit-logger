<?php

declare(strict_types=1);

namespace Zappzarapp\AuditLogger\Encryption;

use Zappzarapp\AuditLogger\Exception\EncryptionException;

interface EncryptionInterface
{
    /**
     * Encrypt plaintext data
     *
     * @throws EncryptionException
     */
    public function encrypt(string $plaintext, string $key): string;

    /**
     * Decrypt ciphertext data
     *
     * @throws EncryptionException
     */
    public function decrypt(string $ciphertext, string $key): string;
}
