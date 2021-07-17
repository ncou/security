<?php

namespace Chiron\Security;

use Chiron\Security\Config\SecurityConfig;
use Chiron\Support\Base64;
use Chiron\Security\Exception\BadSignatureException;
use InvalidArgumentException;

// TODO : ajouter des tests : https://github.com/django/django/blob/56f9579105c324ff15250423bf9f8bdf1634cfb4/tests/signing/tests.py#L187

/**
 * Sign and Unsign a string with a keyed hmac compressed using base64.
 * Inspired by django signing module.
 *
 * @see https://docs.djangoproject.com/en/3.0/_modules/django/core/signing/
 */
final class TimestampSigner
{
    public const SEPARATOR = Signer::SEPARATOR;

    private $signer;

    public function __construct(SecurityConfig $config)
    {
        $this->signer = new Signer($config);
    }

    /**
     * Define a salt to be used with the secret key to namespace the hash.
     *
     * @param string $salt
     * @return self
     */
    public function withSalt(string $salt): self
    {
        // TODO : vérifier que le sel est bien une string cad pas null, éventuellement faire un strval() sur le paramétre $salt !!!!
        // TODO : ajouter une vérification pour le salt du genre :
        /*
        if ($salt !== null && !preg_match('#^[a-zA-Z0-9_.-]{3,50}$#D', $salt))
            throw new BadSignatureException('Malformed salt, only [a-zA-Z0-9_.-]{3,50} characters are acceptable');
        */

        $new = clone $this;
        $new->signer = $this->signer->withSalt($salt);

        return $new;
    }

    /**
     * Sign the value (signature is added after the ":" separator).
     * ex : "My String" will return "My String:ae787d87d87h87....23c"
     *
     * @param string $value
     *
     * @return string
     */
    public function sign(string $value): string
    {
        // TODO : utiliser des concaténation avec le point, plutot qu'un sprintf !!!!
        $timestamped = sprintf('%s%s%s', $value, self::SEPARATOR, dechex(time())); // TODO : utiliser un base62 pour l'encodage du integer !!!!

        return $this->signer->sign($timestamped);
    }

    /**
     * Retrieve original value and check it wasn't signed more than max_age seconds ago.
     *
     * @param string $value Message for unsigning.
     * @param string $maxAge Timestamp or datetime description (presented in format accepted by strtotime).
     *
     * @return string
     */
    // TODO : ajouter les throws dans le phpdoc !!!
    public function unsign(string $value, $maxAge): string
    {
        $result = $this->signer->unsign($value);

        $position = strrpos($result, self::SEPARATOR); // TODO : vérifier quand même ce qui se passe si on ne met pas l'exception en dessous quand strrpos retourne false voir si cela fonctionne quand même.

        // Throw an exception if the separator is not found.
        if ($position === false) {
            throw new BadSignatureException('No timestamp separator found in value.'); //Separator not found in value.
        }

        $value = substr($result, 0, $position);
        $timestamp = substr($result, $position + 1);
        $timestamp = hexdec($timestamp); // TODO : utiliser un base62 decode !!!!

        $maxAge = $this->prepareMaxAge($maxAge);

        if ($maxAge > $timestamp) {
            // TODO : créer une SignatureExpiredException::class qui étend de BadSignatureException::class !!!!
            //throw new BadSignatureException(sprintf('Signature age %d > %d seconds.', $timestamp, $maxAge));
            //throw new BadSignatureException(sprintf('Signature timestamp expired (%d < %d)', $timestamp, time())); // TODO : utiliser plutot le $maxAge dans l'affichage !!!
            throw new BadSignatureException(sprintf('Signature timestamp expired (%d < %d)', $timestamp, $maxAge)); //Signature has expired and is no longer valid!

        }

        return $value;
    }

    /**
     * Return timestamp parsed from English textual datetime description
     *
     * @param string|int $time Timestamp or datetime description (presented in format accepted by strtotime).
     * @return int
     * @throws \Bitrix\Main\ArgumentTypeException
     * @throws \Bitrix\Main\ArgumentException
     */
    // TODO : fonction à améliorer !!!!
    private function prepareMaxAge($time)
    {
        if (!is_string($time) && !is_int($time))
            throw new ArgumentTypeException('time');

        if (is_string($time))
        {
            $timestamp = strtotime($time);
            if (!$timestamp)
                throw new ArgumentException(sprintf('Invalid time "%s" format. See "Date and Time Formats"', $time));
        }
        else
        {
            $timestamp = (int) $time;
        }

        if ($timestamp < time())
            throw new ArgumentException(sprintf('Timestamp %d must be greater than now()', $timestamp));

        return $timestamp;
    }
}
