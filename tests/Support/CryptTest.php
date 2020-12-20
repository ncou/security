<?php

declare(strict_types=1);

namespace Chiron\Security\Tests\Support;

use Chiron\Security\Support\Crypt;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Chiron\Security\Support\Crypt
 */
class CryptTest extends TestCase
{
    public function testWithEmptyString(): void
    {
        $str = '';
        $key = random_bytes(32);

        $ciphertext = Crypt::encrypt($str, $key);

        self::assertSame($str, Crypt::decrypt($ciphertext, $key));
    }

    public function testSuccessEncryptAndDecrypt(): void
    {
        $str = 'MySecretMessageToCrypt';
        $key = random_bytes(32);

        $ciphertext = Crypt::encrypt($str, $key);

        self::assertSame($str, Crypt::decrypt($ciphertext, $key));
    }

    public function testExceptionDecryptWithBadKey(): void
    {
        $str = 'MySecretMessageToCrypt';
        $key = random_bytes(32);
        $badKey = random_bytes(32);

        $ciphertext = Crypt::encrypt($str, $key);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Decryption can not proceed due to invalid ciphertext integrity.');

        Crypt::decrypt($ciphertext, $badKey);
    }

    public function testExceptionEncryptWithKeyTooShort(): void
    {
        $str = 'MySecretMessageToCrypt';

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Bad key length [expecting 32 bytes].');

        $ciphertext = Crypt::encrypt($str, random_bytes(30));
    }

    public function testExceptionDecryptWithKeyTooShort(): void
    {
        $str = 'MySecretMessageToCrypt';

        $ciphertext = Crypt::encrypt($str, random_bytes(32));

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Bad key length [expecting 32 bytes].');

        Crypt::decrypt($ciphertext, random_bytes(30));
    }

    public function testExceptionEncryptWithKeyTooLong(): void
    {
        $str = 'MySecretMessageToCrypt';

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Bad key length [expecting 32 bytes].');

        $ciphertext = Crypt::encrypt($str, random_bytes(34));
    }

    public function testExceptionDecryptWithKeyTooLong(): void
    {
        $str = 'MySecretMessageToCrypt';

        $ciphertext = Crypt::encrypt($str, random_bytes(32));

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Bad key length [expecting 32 bytes].');

        Crypt::decrypt($ciphertext, random_bytes(34));
    }

    public function testExceptionDecryptWithBadCipherText(): void
    {
        $str = 'MySecretMessageToCrypt';
        $key = random_bytes(32);

        $ciphertext = Crypt::encrypt($str, $key);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Decryption can not proceed due to invalid ciphertext integrity.');

        Crypt::decrypt($ciphertext . 'a', $key);
    }

    public function testExceptionDecryptWithCipherTooSmall(): void
    {
        $str = 'MySecretMessageToCrypt';
        $key = random_bytes(32);

        $ciphertext = str_repeat('A', Crypt::MINIMUM_CIPHERTEXT_SIZE - 1);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Decryption can not proceed due to invalid ciphertext length.');

        Crypt::decrypt($ciphertext, $key);
    }

    /**
     * @dataProvider headerPositions
     */
    public function testExceptionDecryptWithBadCipherHeader(int $index): void
    {
        $str = 'MySecretMessageToCrypt';
        $key = random_bytes(32);

        $ciphertext = Crypt::encrypt($str, $key);
        $ciphertext[$index] = chr((ord($ciphertext[$index]) + 1) % 256);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Decryption can not proceed due to invalid ciphertext integrity.');

        Crypt::decrypt($ciphertext, $key);
    }

    /**
     * @return array<array<int>>
     */
    public function headerPositions(): array
    {
        return [
            [0], // the hmac.
            [Crypt::MAC_BYTE_SIZE + 1], // the salt
            [Crypt::MAC_BYTE_SIZE + Crypt::SALT_BYTE_SIZE + 1], // the IV
            [Crypt::MAC_BYTE_SIZE + Crypt::SALT_BYTE_SIZE + Crypt::IV_BYTE_SIZE + 1], // the ciphertext
        ];
    }
}
