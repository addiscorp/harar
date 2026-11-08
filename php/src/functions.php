<?php

declare(strict_types=1);

namespace Harar;

/** What a reference to a vault key starts with, as op:// for 1Password. */
const REFERENCE_PREFIX = 'harar://';

/**
 * harar at `$socket`: by default the per-user agent on this machine
 * (`harar agent`), else a primary (/run/harar.sock). Or, with `$edge` and
 * `$token`, a harar edge, for a service off your network: its URL and a
 * service token from `harar edge token create`, read from the platform's
 * secrets.
 */
function vault(?string $socket = null, ?string $edge = null, ?string $token = null): Vault|EdgeVault
{
    if ($edge !== null || $token !== null) {
        if ($socket !== null) {
            throw new \InvalidArgumentException('Harar\vault(): a socket or an edge, not both');
        }
        return new EdgeVault($edge ?? '', $token ?? '');
    }
    return new Vault($socket ?? agent_socket());
}

/** The vault key `$value` names, if the whole value is a harar:// reference. */
function reference(string $value): ?string
{
    if (!str_starts_with($value, REFERENCE_PREFIX)) {
        return null;
    }
    $key = substr($value, strlen(REFERENCE_PREFIX));
    return $key !== '' && preg_match('/\s/u', $key) === 0 ? $key : null;
}

/** Where the per-user agent (`harar agent`) listens: the harar binary's rule. */
function agent_socket(): string
{
    $home = getenv('HOME');
    $runtime = getenv('XDG_RUNTIME_DIR');
    if (PHP_OS_FAMILY === 'Darwin' && is_string($home) && $home !== '') {
        return "{$home}/Library/Application Support/harar/agent.sock";
    }
    if (is_string($runtime) && $runtime !== '') {
        return "{$runtime}/harar/agent.sock";
    }
    return (is_string($home) && $home !== '' ? $home : '') . '/.harar/agent.sock';
}
