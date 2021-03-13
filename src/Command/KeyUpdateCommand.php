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
            ->addOption('mount', 'm', InputOption::VALUE_REQUIRED, 'Mount security key into given file')
            ->addOption('placeholder', 'p', InputOption::VALUE_OPTIONAL, 'Placeholder of security key (will attempt to use current encryption key if empty)');
    }

    protected function perform(Environment $environment, Filesystem $filesystem, SecurityConfig $securityConfig): int
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

        $placeholder = $this->option('placeholder');
        // The placeholder is not defined
        if ($placeholder === null) {
            $placeholder = $securityConfig->getKey();
        }

        $updated = $this->updateEnvironmentFile($filesystem, $filepath, $placeholder);

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
     * @param  Filesystem  $filesystem
     * @param  string      $filepath
     * @param  string      $placeholder
     *
     * @return bool Return if the file has been updated or not.
     */
    private function updateEnvironmentFile(Filesystem $filesystem, string $filepath, string $placeholder): bool
    {
        // TODO si le placeholder est vide dans ce cas retourner "false" !!!!

        $key = Random::hex(SecurityConfig::KEY_BYTES_SIZE);

        $content = preg_replace(
            sprintf('/%s/', $placeholder),
            $key,
            $filesystem->read($filepath),
            1,
            $counter
        );

        // The variable $counter is filled with the number of replacements done.
        if ($counter === 1) {
            $filesystem->write($filepath, $content);

            return true;
        }

        return false;


        /*
        $oldKey = $environment->get('APP_KEY');
        $newKey = Random::hex(SecurityConfig::KEY_BYTES_SIZE);

        $content = preg_replace(
            sprintf('/^APP_KEY=%s/m', $oldKey),
            'APP_KEY=' . $newKey,
            $filesystem->read($filepath),
            1,
            $counter
        );

        // The variable $counter is filled with the number of replacements done.
        if ($counter === 1) {
            $filesystem->write($filepath, $content);

            return true;
        }

        return false;*/
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
    private function updateEnvironmentFile_SAVE(Environment $environment, Filesystem $filesystem, string $filepath): bool
    {
        $oldKey = $environment->get('APP_KEY');
        $newKey = Random::hex(SecurityConfig::KEY_BYTES_SIZE);

        $content = preg_replace(
            sprintf('/^APP_KEY=%s/m', $oldKey),
            'APP_KEY=' . $newKey,
            $filesystem->read($filepath),
            1,
            $counter
        );

        // The variable $counter is filled with the number of replacements done.
        if ($counter === 1) {
            $filesystem->write($filepath, $content);

            return true;
        }

        return false;
    }
}

