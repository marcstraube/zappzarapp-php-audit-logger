<?php

declare(strict_types=1);

namespace Zappzarapp\AuditLogger\Encryption;

use Random\RandomException;
use Zappzarapp\AuditLogger\Exception\EncryptionException;

final readonly class AppEncryption implements EncryptionInterface
{
    private const string CIPHER     = 'aes-256-gcm';

    private const int IV_LENGTH     = 12;

    private const int TAG_LENGTH    = 16;

    private const int KEY_LENGTH    = 32;

    private const string HKDF_INFO  = 'audit-logger-encryption';

    /** @noinspection PhpComposerExtensionStubsInspection - ext-openssl is optional (suggest), required only for AppEncryption */
    public function encrypt(string $plaintext, string $key): string
    {
        try {
            $iv = random_bytes(self::IV_LENGTH);
        } catch (RandomException $randomException) { // @codeCoverageIgnore
            throw new EncryptionException('Failed to generate random IV: ' . $randomException->getMessage(), 0, $randomException); // @codeCoverageIgnore
        }

        $derivedKey = hash_hkdf('sha256', $key, self::KEY_LENGTH, self::HKDF_INFO);

        $tag = '';

        $ciphertext = openssl_encrypt(
            $plaintext,
            self::CIPHER,
            $derivedKey,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            '',
            self::TAG_LENGTH
        );

        if ($ciphertext === false) {
            throw new EncryptionException('Failed to encrypt data: ' . openssl_error_string()); // @codeCoverageIgnore
        }

        return base64_encode($iv . $tag . $ciphertext);
    }

    /** @noinspection PhpComposerExtensionStubsInspection - ext-openssl is optional (suggest), required only for AppEncryption */
    public function decrypt(string $ciphertext, string $key): string
    {
        $decoded = base64_decode($ciphertext, true);
        if ($decoded === false) {
            throw new EncryptionException('Failed to decode base64 ciphertext');
        }

        $ivLength  = self::IV_LENGTH;
        $tagLength = self::TAG_LENGTH;
        $minLength = $ivLength + $tagLength;

        if (strlen($decoded) < $minLength) {
            throw new EncryptionException('Ciphertext is too short to contain IV and tag');
        }

        $iv            = substr($decoded, 0, $ivLength);
        $tag           = substr($decoded, $ivLength, $tagLength);
        $ciphertextRaw = substr($decoded, $ivLength + $tagLength);

        $derivedKey = hash_hkdf('sha256', $key, self::KEY_LENGTH, self::HKDF_INFO);

        $plaintext = openssl_decrypt(
            $ciphertextRaw,
            self::CIPHER,
            $derivedKey,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        if ($plaintext === false) {
            /** @infection-ignore-all: GCM returns empty error string */
            throw new EncryptionException('Failed to decrypt data: ' . openssl_error_string());
        }

        return $plaintext;
    }
}
