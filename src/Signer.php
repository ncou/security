<?php

namespace Chiron\Security;

use Chiron\Security\Config\SecurityConfig;
use Chiron\Security\Support\Base64;
use Chiron\Security\Exception\BadSignatureException;
use InvalidArgumentException;

//https://github.com/ilkivv/atleteraru/blob/7df8594924caceb13eebe64bdd7ec7c91fe5c0a1/bitrix/modules/main/lib/security/sign/timesigner.php
//https://github.com/Kyslik/django-signer/blob/master/src/Signer.php

// BASE62 :
// https://snipplr.com/view/22246/base62-encode--decode
// https://programanddesign.com/php/base62-encode/
// https://github.com/daqimei/base62/blob/master/src/Base62.php
// https://github.com/songying/Base62/blob/master/base62.php
// https://github.com/breenie/base62/blob/master/src/Kurl/Maths/Encode/Driver/PurePhpEncoder.php
// https://gist.github.com/jgrossi/a4eb21bbe00763d63385
// https://github.com/vinkla/base62/blob/master/src/Base62.php

// TODO : sinon utiliser dechex et hexdec en repmplacement de la fonction Base62 pour réduire les integers

// BASE 64 :
// https://base64.guru/developers/php/examples/base64url
// https://github.com/firebase/php-jwt/blob/master/src/JWT.php#L333
// https://www.php.net/manual/fr/function.base64-decode.php#118244

// TODO : Random exemple de classes : https://github.com/phalcon/phalcon/blob/569afa77b84d4907f121fef16a0db88c22d52ef7/src/Support/Str/Random.php
// https://github.com/phalcon/cphalcon/blob/634e7233a86780c9509614a8d835b188c8be76e5/phalcon/Security/Random.zep
// https://github.com/phalcon/cphalcon/blob/81561d8abd33449458c99873d2ddaeaa7832ebd0/phalcon/Helper/Str.zep#L611
// https://github.com/ircmaxell/RandomLib/blob/master/lib/RandomLib/Generator.php#L118

// TODO : exemple pour SIGNER les cookies.
// https://docs.djangoproject.com/en/3.0/_modules/django/core/signing/
// https://github.com/tj/node-cookie-signature/blob/master/index.js
// TODO : vérification si le SIGNED cookie commence bien par "s:"
//https://github.com/expressjs/cookie-parser/blob/master/index.js#L134
//https://github.com/balderdashy/sails/blob/53d0473c2876b1925136f777cb51ac9eda5b24aa/lib/hooks/session/index.js#L513

// TODO : exemple pour vérifier les cookies signés (doivent commencer par 's:')
//https://github.com/balderdashy/sails/blob/53d0473c2876b1925136f777cb51ac9eda5b24aa/lib/hooks/session/index.js#L481
//https://github.com/expressjs/cookie-parser/blob/master/index.js#L129
//https://github.com/expressjs/session/blob/master/index.js#L656


//https://github.com/ircmaxell/RandomLib/blob/master/lib/RandomLib/Generator.php

//https://github.com/hackzilla/password-generator/blob/master/Generator/ComputerPasswordGenerator.php#L38
//https://github.com/icecave/abraxas/blob/e969b3683817e1c779297d195bfda37ba6ddcace/src/PasswordGenerator.php#L123
//https://github.com/mrhewitt/php-utils/blob/dd842f263339ba4e6003ff981299fa7b45140dfa/src/MarkHewitt/Util/PWGen.php#L394

//https://paragonie.com/blog/2015/07/common-uses-for-csprngs-cryptographically-secure-pseudo-random-number-generators
//https://paragonie.com/blog/2015/07/how-safely-generate-random-strings-and-integers-in-php


//https://docs.phalcon.io/4.0/fr-fr/api/phalcon_security#security-random

/*
$random = new Random();

// ...
$bytes      = $random->bytes();

// Generate a random hex string of length $len.
$hex        = $random->hex($len);

// Generate a random base64 string of length $len.
$base64     = $random->base64($len);

// Generate a random URL-safe base64 string of length $len.
$base64Safe = $random->base64Safe($len);

// Generate a UUID (version 4).
// See https://en.wikipedia.org/wiki/Universally_unique_identifier
$uuid       = $random->uuid();

// Generate a random integer between 0 and $n.
$number     = $random->number($n);
*/

// TODO : renommer la classe en "Security", et créer 2 méthode generateKey() qui retourn un randombyte et un generateId ou uniqueId qui génére une string aléatoire. Et aussi créer la méthode randomString($length, $alphabet) avec des constante pluc dans classe (style UPPER/LOWER/SYMBOLS/AMBIGUOIUS etc...)

// TODO : créer des méthodes globales (dans functions.php) style uuid() ou generate_key() et random_id() et sign() et unsign() pour simplifier l'utilisation de ces méthodes !!!

/**
 * Sign and Unsign a string with a keyed hmac compressed using base64.
 * Inspired by django signing module.
 *
 * @see https://docs.djangoproject.com/en/3.0/_modules/django/core/signing/
 */
final class Signer
{
    public const SEPARATOR = ':';
    /**
     * The 256 bit/32 byte binary key to use as a secret key.
     *
     * @var string
     */
    private $key;

    /**
     * Salt can be used to namespace the hash, so that a signed string is
     * only valid for a given namespace. Leaving this at the default
     * value or re-using a salt value across different parts of your
     * application without good cause is a security risk.
     *
     * @var string
     */
    private $salt = '';

    public function __construct(SecurityConfig $config)
    {
        $this->key = $config->getRawKey();
    }

    /**
     * Define a salt to be used with the secret key to namespace the hash.
     *
     * @param string $salt
     * @return self
     */
    public function withSalt(string $salt): self
    {
        $new = clone $this;
        $new->salt = $salt;

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
        // Generate a salted keyed binary hash used as signature.
        $hmac = hash_hmac('sha256', $value, $this->salt . $this->key, true);

        return $value . self::SEPARATOR . Base64::encode($hmac);
    }

    /**
     * Unsign the value (signature after the ":" separator is removed).
     * ex : "My String:ae787d87d87h87....23c" will return "My String"
     *
     * @param string $value
     *
     * @throws BadSignatureException Exception in case signature is invalid.
     *
     * @return string Return the value if signature is valid.
     */
    public function unsign(string $value): string
    {
        $position = strrpos($value, self::SEPARATOR); // TODO : vérifier quand même ce qui se passe si on ne met pas l'exception en dessous quand strrpos retourne false voir si cela fonctionne quand même.

        // Throw an exception if the separator is not found.
        if ($position === false) {
            throw new BadSignatureException('No signature separator found in value.'); //Separator not found in value.
        }

        $data = substr($value, 0, $position);
        $signed = static::sign($data, $this->key);

        if (hash_equals($value, $signed)) {
            return $data;
        }

        throw new BadSignatureException('Signature value does not match.');
    }

    /**
     * Return a URL-safe base64-encoded hash of the input $value
     *
     * @param string $value
     * @return string
     */
    /*
    public function hashBase64(string $value): string
    {
        $binaryHash = hash_hmac('sha1', $value, $this->secret . 'signer', true);
        $base64 = base64_encode($binaryHash);
        $base64UrlSafe = str_replace(array('+', '/'), array('-', '_'), $base64);

        return rtrim($base64UrlSafe, '=');
    }*/
}
