<?php

declare(strict_types=1);

namespace Chiron\Security\Bootloader;

use Chiron\Core\Container\Bootloader\AbstractBootloader;
use Chiron\Console\Console;
use Chiron\Security\Command\KeyUpdateCommand;
use Chiron\Security\Command\KeyGenerateCommand;

final class SecurityCommandsBootloader extends AbstractBootloader
{
    public function boot(Console $console): void
    {
        $console->addCommand(KeyUpdateCommand::getDefaultName(), KeyUpdateCommand::class);
        $console->addCommand(KeyGenerateCommand::getDefaultName(), KeyGenerateCommand::class);
    }
}
