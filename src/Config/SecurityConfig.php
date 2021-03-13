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

    public const KEY_BYTES_SIZE = 32;

    protected function getConfigSchema(): Schema
    {
        return Expect::structure([
            'key' => Expect::xdigit()->assert(Closure::fromCallable([$this, 'assertKeyLength']), 'invalid key length.')->default(env('APP_KEY')),
        ]);
    }

    // TODO : utiliser un paramétre bool $force_bytes ou $raw dans cette méthode get pour forcer le retour avec hex2bin ????
    public function getKey(): string
    {
        return $this->get('key');
    }

    public function getRawKey(): string
    {
        return hex2bin($this->getKey());
    }

    /**
     * Length of the key should be twice (x2) the bytes size because it's hexa encoded.
     */
    private function assertKeyLength(string $value): bool
    {
        return strlen($value) === self::KEY_BYTES_SIZE * 2;
    }
}
