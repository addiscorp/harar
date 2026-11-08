<?php

declare(strict_types=1);

namespace Harar;

/**
 * harar:// references resolved to their values, the shape of 1Password's
 * client.secrets.resolve('op://...'). Read when asked for; held only by you.
 */
final class Secrets
{
    /** @param \Closure(array<string, string>, string): array<mixed> $ask one request to harar, and its answer */
    public function __construct(private readonly \Closure $ask)
    {
    }

    /** The value `$ref` (harar://prod/shop/STRIPE_KEY) names. */
    public function resolve(string $ref): string
    {
        $key = reference($ref);
        if ($key === null) {
            throw new HararError('not a harar:// reference: ' . json_encode($ref, JSON_UNESCAPED_SLASHES));
        }
        $value = ($this->ask)(['op' => 'get', 'key' => $key], $ref)['value'] ?? null;
        if (!is_string($value)) {
            throw new HararError("harar sent no value for {$ref}");
        }
        return $value;
    }

    /**
     * Each reference's value, in order; the first that fails is the error.
     *
     * @param list<string> $refs
     * @return list<string>
     */
    public function resolveAll(array $refs): array
    {
        return array_map($this->resolve(...), $refs);
    }
}
