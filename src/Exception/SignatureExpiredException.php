<?php

declare(strict_types=1);

namespace Chiron\Security\Exception;

class SignatureExpiredException extends BadSignatureException
{
    //Signature timestamp is older than required max_age.
}
