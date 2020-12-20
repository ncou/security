<?php

namespace Chiron\Security\Support;

use InvalidArgumentException;

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

final class Random
{
    /**
     * Generate a secure random unique key.
     * If the $raw value is false an hexadecimal encoding is applied.
     * In hexa, the string output length is $bytes X 2 in the range [0123456789abcdef].
     *
     * @param int $bytes Size in bytes for the generated key
     * @param bool $raw Apply (or not) an hexa decimal encoding
     *
     * @return string Return as lowercase hexits unless $raw is set to true in which case the raw binary value is returned.
     */
    public static function generateKey(int $bytes = 32, bool $raw = true): string
    {
        if ($bytes < 1) {
            throw new InvalidArgumentException('Invalid key bytes size value.'); // TODO : indiquer dans le message un truc du genre : should be above 0 ou should be/expect a positive integer
        }

        $key = random_bytes($bytes);

        return $raw ? $key : bin2hex($key);
    }

    public static function hex(int $bytes = 32): string
    {
        return static::generateKey($bytes, false);
    }

    public static function bytes(int $bytes = 32): string
    {
        return static::generateKey($bytes, true);
    }

    /**
     * Generate a random string identifier.
     *
     * @param int $length      Length of the random string to generate
     * @param bool $easyToRead Prevent ambiguous characters in the result
     *
     * @return string
     */
    // TODO : Utiliser ce bout de code pour améliorer l'algo:       https://github.com/nette/utils/blob/master/src/Utils/Random.php#L26
    public static function randomId(int $length = 32, bool $easyToRead = false): string
    {
        if ($length < 1) {
            throw new InvalidArgumentException('Invalid identifier length value.'); // TODO : indiquer dans le message un truc du genre : should be above 0 ou should be/expect a positive integer
        }

        $alphabet = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';

        if ($easyToRead) {
            // remove ambiguous characters.
            $alphabet = str_replace(str_split('B8G6I1l0OQDS5Z2'), '', $alphabet);
        }

        $str = '';
        $maxLength = strlen($alphabet) - 1;
        for ($i = 0; $i < $length; ++$i) {
            $str .= $alphabet[random_int(0, $maxLength)];
        }

        return $str;
    }

    public static function alphanum(int $length = 32, bool $easyToRead = false): string
    {
        return static::randomId($length, $easyToRead);
    }

/*
    function str_rand(int $length = 64){ // 64 = 32
        $length = ($length < 4) ? 4 : $length;
        return bin2hex(random_bytes(($length-($length%2))/2));
    }

    var_dump(str_rand());
    // d6199909d0b5fdc22c9db625e4edf0d6da2b113b21878cde19e96f4afe69e714
    */


    /**
     * Return a UUID (version 4) using random bytes
     * Note that version 4 follows the format:
     *     xxxxxxxx-xxxx-4xxx-Yxxx-xxxxxxxxxxxx
     * where Y is one of: [8, 9, a, b]
     *
     * @return string
     */
    public static function uuid(): string
    {
        return implode('-', [
            bin2hex(random_bytes(4)),
            bin2hex(random_bytes(2)),
            bin2hex(chr((ord(random_bytes(1)) & 0x0F) | 0x40)) . bin2hex(random_bytes(1)),
            bin2hex(chr((ord(random_bytes(1)) & 0x3F) | 0x80)) . bin2hex(random_bytes(1)),
            bin2hex(random_bytes(6))
        ]);
    }
}
