<?php

declare(strict_types=1);

namespace Harar;

/** harar at `$socket`: a per-user agent or a primary. */
function vault(string $socket): Vault
{
    return new Vault($socket);
}
