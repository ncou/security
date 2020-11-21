<?php

declare(strict_types=1);

namespace Chiron\Security\Bootloader;

use Chiron\Core\Container\Bootloader\AbstractBootloader;
use Chiron\Console\Console;
use Chiron\Command\KeyGenerateCommand;
use Chiron\Command\KeyUpdateCommand;

final class KeyCommandsBootloader extends AbstractBootloader
{
    public function boot(Console $console): void
    {
        $console->addCommand(KeyGenerateCommand::getDefaultName(), KeyGenerateCommand::class);
        $console->addCommand(KeyUpdateCommand::getDefaultName(), KeyUpdateCommand::class);
    }
}
