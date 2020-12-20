<?php

declare(strict_types=1);

namespace Chiron\Security\Exception;

use RuntimeException;

class BadSignatureException extends RuntimeException
{
    //Signature does not match.
}
