<?php

declare(strict_types=1);

namespace Chiron\Security\Config;

use Chiron\Config\AbstractInjectableConfig;
use Nette\Schema\Expect;
use Nette\Schema\Schema;
use Closure;

// TODO : créer une Facade 'Security::class' pour cette classe pour récupérer la clés via la méthode Security::getKey() ou Security::getRawKey()

final class SecurityConfig extends AbstractInjectableConfig
{
    protected const CONFIG_SECTION_NAME = 'security';

    public const KEY_BYTES_SIZE = 32; // TODO : renommer la constante en KEY_SIZE et indiquer dans le commentaire que c'est des bytes.

    protected function getConfigSchema(): Schema
    {
        // TODO : améliorer la vérification sur la longueur car c'est pas super propre de faire un min + un max.
        return Expect::structure([
            //'key' => Expect::xdigit()->assert(Closure::fromCallable([$this, 'assertKeyLength']), 'invalid key length.')->default(env('APP_KEY')),
            'key' => Expect::string()->min(self::KEY_BYTES_SIZE)->max(self::KEY_BYTES_SIZE)->default(env('APP_KEY')),
        ]);
    }

    public function getKey(): string
    {
        return $this->get('key');
    }

    /**
     * Length of the key should be twice (x2) the bytes size because it's hexa encoded.
     */
    /*
    private function assertKeyLength(string $value): bool
    {
        // Il faudrait pas plutot utiliser le fonction mb_strlen($string, '8bit') ???? éventuellement utiliser directement le support Str::class
        return strlen($value) === self::KEY_BYTES_SIZE * 2;
    }*/
}
