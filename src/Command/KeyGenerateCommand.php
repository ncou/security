<?php

declare(strict_types=1);

namespace Chiron\Security\Command;

use Chiron\Core\Command\AbstractCommand;
use Chiron\Security\Config\SecurityConfig;
use Chiron\Filesystem\Filesystem;
use Chiron\Support\Random;
use Symfony\Component\Console\Input\InputOption;

//key:generate --iterations=10
//key:generate -i 10

final class KeyGenerateCommand extends AbstractCommand
{
    protected static $defaultName = 'key:generate';

    protected function configure()
    {
        $this
            ->setDescription('Generate a random security key.')
            ->addOption('iterations', 'i', InputOption::VALUE_REQUIRED, 'How many keys to generate?', 1);
    }

    protected function perform(Filesystem $filesystem): int
    {
        $iterations = $this->option('iterations');

        if (! is_numeric($iterations) || (int) $iterations < 1) {
            $this->error('Invalid iterations value used, expecting an integer above 0.');

            return self::FAILURE;
        }

        $this->info("Generated security key(s)");

        for ($i = 0; $i < $iterations; $i++) {
            //$this->message(Random::hex(SecurityConfig::KEY_BYTES_SIZE));
            $this->message($this->wrapAsBase64(Random::bytes(SecurityConfig::KEY_BYTES_SIZE)));
        }

        return self::SUCCESS;
    }

    private function wrapAsBase64(string $key): string
    {
        return 'base64:' . base64_encode($key); // TODO : utiliser la classe Support\Base64::class ????
    }
}
