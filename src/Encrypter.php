<?php

declare(strict_types=1);

namespace Chiron\Security;

use Chiron\Security\Exception\DecryptException;
use Chiron\Security\Exception\EncryptException;
use Chiron\Security\Config\SecurityConfig;
use Chiron\Security\Support\Crypt;
use Throwable;
use RuntimeException;

//https://github.com/spiral/encrypter/blob/master/src/Exception/EncrypterException.php
//https://github.com/spiral/encrypter/blob/master/src/Exception/DecryptException.php
//https://github.com/spiral/encrypter/blob/master/src/Exception/EncryptException.php

//https://github.com/spiral/encrypter/blob/master/src/Encrypter.php
//https://github.com/cakephp/cakephp/blob/42353085a8911745090024e2a4f43215d38d6af0/src/Utility/CookieCryptTrait.php

// TODO : déplacer ces classe dans le package chiron/security ???? Voir même déplacer ces méthode encrypt($value, $key) et decrypt($value, $key) directement dans la classe Security::class ??? Par contre on devra passer la clés en paramétre de ces 2 méthodes mais ce n'est pas un probléme !!!!

// TODO : renommer la classe en Crypt ou Crypter et la déplacer dans le package chiron/security et ajouter une dépendance au package chiron/encrypter
final class Encrypter
{
    /**
     * The 256 bit/32 byte binary key to use as a secret key.
     *
     * @var string
     */
    private $key;

    public function __construct(SecurityConfig $config)
    {
        $this->key = $config->getKey();
    }

    /**
     * Encrypts $value
     *
     * @param string|array $value Value to encrypt
     *
     * @return string Encoded values
     */
    // TODO : lever une exception si les données passées en entrée sont de type is_object ou is_ressource, car on ne peut encrypter que des : is_scalar / is_null et is_array   et encore l'encryptage d'entiers/décimaux/null n'a pas vraiment de sens !!!!
    // TODO : utiliser plutot des unserialize et des serialize à la place des json_encode et json_decode car ils peuvent convertire les chaines 'false' 'true' ou 'null' en booléen et donc perdre le type d'objet !!!! https://github.com/laravel/framework/blob/8.x/src/Illuminate/Session/Store.php#L98   /    https://github.com/laravel/framework/blob/8.x/src/Illuminate/Session/Store.php#L129
    public function encrypt($data): string
    {
        // TODO : il faudrait pas vérifier que le json_encode fonctionne ??? il y a un risque d'avoir une exception, ou à minima un $data qui sera à false !!!! Eventuellement vérifier que le $data est bien un is_array ou is_string en entrée et sinon lever une EncryptException !!!
        $data = json_encode($data);
        //$data = serialize($data);

        try {
            return base64_encode(Crypt::encrypt($data, $this->key));
        } catch (Throwable $e) {
            throw new EncryptException($e->getMessage(), $e->getCode(), $e);
        }
    }

    /**
     * Decrypts $value
     *
     * @param string $ciphertext Values to decrypt
     *
     * @return string|array Decrypted values
     */
    public function decrypt(string $ciphertext)
    {
        try {
            $result = Crypt::decrypt(base64_decode($ciphertext), $this->key);

            // TODO : attention ca peut retourner null si la string à décoder n'est pas un json valide !!!! il faudrait vérifier que le résultat est un is_string() OU is_array(), sinon on retourne une chaine vide !!!!
            return json_decode($result, true);

            //return unserialize($result);

        } catch (Throwable $e) {
            throw new DecryptException($e->getMessage(), $e->getCode(), $e);
        }
    }
}
