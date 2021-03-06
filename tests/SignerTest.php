<?php

declare(strict_types=1);

namespace Chiron\Security\Tests;

use Chiron\Security\Signer;
use Chiron\Security\Exception\BadSignatureException;
use Chiron\Support\Random;
use Chiron\Container\Container;
use Chiron\Security\Config\SecurityConfig;
use PHPUnit\Framework\TestCase;

// TODO : finir d'ajouter les tests, notamment la vérification sur les throw DecyptException en EncryptException !!!

/**
 * @covers \Chiron\Security\Signer
 */
class SignerTest extends TestCase
{
    private $container;
    private $signer;

    public function setUp(): void
    {
        $this->container = new Container();

        $key = Random::hex(SecurityConfig::KEY_BYTES_SIZE);
        $securityConfig = new SecurityConfig(['key' => $key]);

        $this->signer = new Signer($securityConfig);
    }

    public function testSignAndUnsign(): void
    {
        $source = 'foobar';

        $signed = $this->signer->sign($source);
        $unsigned = $this->signer->unsign($signed);

        self::assertEquals($source, $unsigned);
    }

    public function testSignAndUnsignWithSalt(): void
    {
        $source = 'foobar';

        $signer1 = $this->signer->withSalt('namespace_1');

        $signed1 = $signer1->sign($source);
        $unsigned1 = $signer1->unsign($signed1);

        $signer2 = $this->signer->withSalt('namespace_2');

        $signed2 = $signer2->sign($source);
        $unsigned2 = $signer2->unsign($signed2);

        self::assertEquals($source, $unsigned1);
        self::assertEquals($source, $unsigned2);
        self::assertEquals($unsigned1, $unsigned2);

        self::assertNotEquals($signed1, $signed2);
    }

    public function testUnsignFailBecauseSeparatorIsMissing(): void
    {
        $this->expectException(BadSignatureException::class);
        $this->expectExceptionMessage('No signature separator found in value.');

        $badSigned = 'separator_is_missing';

        $unsigned = $this->signer->unsign($badSigned);
    }

    public function testUnsignFailBecauseSignatureIsInvalid(): void
    {
        $this->expectException(BadSignatureException::class);
        $this->expectExceptionMessage('Signature value does not match.');

        $source = 'foobar';
        $signed = $this->signer->sign($source);
        $badSigned = $signed . '-modified';

        $unsigned = $this->signer->unsign($badSigned);
    }
}
