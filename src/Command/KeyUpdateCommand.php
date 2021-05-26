<?php

declare(strict_types=1);

namespace Chiron\Security\Command;

use Chiron\Core\Command\AbstractCommand;
use Chiron\Core\Environment;
use Chiron\Filesystem\Filesystem;
use Chiron\Security\Config\SecurityConfig;
use Chiron\Support\Random;
use Symfony\Component\Console\Input\InputOption;

final class KeyUpdateCommand extends AbstractCommand
{
    protected static $defaultName = 'key:update';

    protected function configure()
    {
        $this
            ->setDescription('Update the security key value in the given file.')
            ->addOption('mount', 'm', InputOption::VALUE_REQUIRED, 'Mount security key into given file');
    }

    protected function perform(SecurityConfig $securityConfig, Filesystem $filesystem): int
    {
        $filepath = $this->option('mount');

        if ($filepath === null) {
            $this->error('The option value for "--mount" is required.');

            return self::FAILURE;
        }

        if ($filesystem->missing($filepath)) {
            $this->error(sprintf('Unable to find file [%s].', $filepath));

            return self::FAILURE;
        }

        $updated = $this->updateEnvironmentFile($securityConfig, $filesystem, $filepath);

        if ($updated) {
            $this->success('Security key has been updated.');
        } else {
            $this->warning('Security key was not updated!');
        }

        return self::SUCCESS;
    }

    /**
     * Update the environment file with the new security key.
     * Security key is by default a random 32 bytes hexabits.
     *
     * @param  Environment $environment
     * @param  Filesystem  $filesystem
     * @param  string      $filepath
     *
     * @return bool Return if the file has been updated or not.
     */
    private function updateEnvironmentFile(SecurityConfig $securityConfig, Filesystem $filesystem, string $filepath): bool
    {
        $oldKey = $securityConfig->getKey();
        $newKey = $this->wrapAsBase64(Random::bytes(SecurityConfig::KEY_BYTES_SIZE));

        $content = preg_replace(
            $this->keyReplacementPattern($oldKey),
            'APP_KEY=' . $newKey,
            $filesystem->read($filepath),
            1,
            $counter
        );

        // The variable $counter is filled with the number of replacements done.
        if ($counter === 1) {
            $filesystem->write($filepath, $content);

            if ($this->isVerbose()) {
                $this->sprintf("<info>New key:</info> <fg=cyan>%s</fg=cyan>\n", $newKey);
            }

            return true;
        }

        return false;
    }

    // TODO : code à rendre plus propre/simple pour toute cette classe !!!!
    private function wrapAsBase64(string $key): string
    {
        return 'base64:' . base64_encode($key); // TODO : utiliser la classe Support\Base64::class ????
    }

    /**
     * Get a regex pattern that will match env APP_KEY with any random key.
     *
     * @return string
     */
    protected function keyReplacementPattern(string $oldKey): string
    {
        $escaped = preg_quote('='.$this->wrapAsBase64($oldKey), '/');

        return "/^APP_KEY{$escaped}/m";
    }
}

