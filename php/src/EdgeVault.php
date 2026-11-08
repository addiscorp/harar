<?php

declare(strict_types=1);

namespace Harar;

/**
 * A vault at a harar edge (docs/edge.md): it resolves references, and only
 * those its service token may read. hosts and send are for gateways on
 * harar's local socket.
 */
final class EdgeVault
{
    /** A harar edge service token, as `harar edge token create` makes it. */
    private const TOKEN = '/\Aharar_edge_[0-9a-f]{16}_[A-Za-z0-9_-]{43}\z/';
    /** https://, or http:// to this machine only. */
    private const URL = '~\A(https://[^/]|http://(127\.0\.0\.1|localhost|\[::1\])([:/]|\z))~';

    public readonly EdgeSecrets $secrets;

    public function __construct(string $edge, string $token)
    {
        if (preg_match(self::URL, $edge) !== 1) {
            throw new \InvalidArgumentException('Harar\vault(edge:): the edge is an https:// URL');
        }
        if (preg_match(self::TOKEN, $token) !== 1) {
            throw new \InvalidArgumentException('Harar\vault(edge:, token:): the token is a harar edge service token (harar edge token create)');
        }
        $this->secrets = new EdgeSecrets(rtrim($edge, '/'), $token);
    }
}
