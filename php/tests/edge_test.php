<?php

// The client against a stand-in harar edge over HTTP: what it sends is the
// edge's POST /v1/resolve (docs/edge.md §5) with the service token, and every
// way the edge can say no is an error naming why. The same cases as
// js/test/edge.test.js.
// Run: php php/tests/edge_test.php (exits non-zero on the first failure).

declare(strict_types=1);

require __DIR__ . '/../src/HararError.php';
require __DIR__ . '/../src/Secrets.php';
require __DIR__ . '/../src/Vault.php';
require __DIR__ . '/../src/EdgeSecrets.php';
require __DIR__ . '/../src/EdgeVault.php';
require __DIR__ . '/../src/functions.php';

use Harar\EdgeVault;
use Harar\HararError;
use function Harar\vault;

const TOKEN = 'harar_edge_0123456789abcdef_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

function check(bool $ok, string $what): void
{
    if (!$ok) {
        throw new LogicException("failed: {$what}");
    }
}

function refuses(callable $f, string $class, string $why): Throwable
{
    try {
        $f();
    } catch (Throwable $e) {
        check($e instanceof $class, "{$class}, got " . $e::class . ': ' . $e->getMessage());
        check(preg_match($why, $e->getMessage()) === 1, "'{$e->getMessage()}' matches {$why}");
        return $e;
    }
    check(false, "an error matching {$why}");
}

/** Runs $test against a stand-in edge: "stripe", or [status, body] for every request. */
function edge(string|array $reply, callable $test): void
{
    $dir = sys_get_temp_dir() . '/harar-php-edge-' . bin2hex(random_bytes(4));
    mkdir($dir, 0700);
    $log = "{$dir}/requests";
    $answer = "{$dir}/answer";
    file_put_contents($answer, json_encode($reply));
    touch($log);
    $proc = proc_open(
        [PHP_BINARY, __DIR__ . '/edge-stand-in.php', $log, $reply === 'stripe' ? 'stripe' : $answer],
        [1 => ['pipe', 'w'], 2 => STDERR],
        $pipes,
    );
    try {
        $port = trim((string) fgets($pipes[1]));
        check(ctype_digit($port), 'the stand-in started');
        $test("http://127.0.0.1:{$port}/functions/v1/harar-edge/", fn () => array_map(
            fn ($l) => json_decode($l, true),
            file($log, FILE_IGNORE_NEW_LINES),
        ));
    } finally {
        proc_terminate($proc);
        proc_close($proc);
        array_map('unlink', glob("{$dir}/*"));
        rmdir($dir);
    }
}

// an edge vault resolves with one POST of /v1/resolve, the service token as its bearer
edge('stripe', function (string $url, callable $requests) {
    $v = vault(edge: $url, token: TOKEN);
    check($v instanceof EdgeVault, 'an edge vault');
    check($v->secrets->resolve('harar://prod/shop/STRIPE_KEY') === 'sk_live_real', 'resolve');
    check($v->secrets->resolveAll(['harar://prod/shop/STRIPE_KEY', 'harar://prod/shop/OTHER']) === ['sk_live_real', 'other'], 'resolveAll');
    check($v->secrets->resolveAll([]) === [], 'resolveAll of nothing');
    refuses(
        fn () => $v->secrets->resolve('harar://prod/site/DATABASE_URL'),
        HararError::class,
        '~harar refused harar://prod/site/DATABASE_URL: not_allowed: this caller may not read~',
    );
    foreach (['prod/shop/STRIPE_KEY', 'op://Prod/Stripe/credential', 'harar://', 'harar://a b'] as $notOne) {
        refuses(fn () => $v->secrets->resolve($notOne), HararError::class, '~not a harar:// reference~');
    }
    refuses(fn () => $v->secrets->resolveAll(['harar://prod/shop/OTHER', 'nope']), HararError::class, '~not a harar:// reference: "nope"~');
    $expect = fn (array $refs) => [
        'method' => 'POST',
        'url' => '/functions/v1/harar-edge/v1/resolve',
        'auth' => 'Bearer ' . TOKEN,
        'type' => 'application/json',
        'body' => ['refs' => $refs],
    ];
    check($requests() === [
        $expect(['harar://prod/shop/STRIPE_KEY']),
        $expect(['harar://prod/shop/STRIPE_KEY', 'harar://prod/shop/OTHER']),
        $expect(['harar://prod/site/DATABASE_URL']),
    ], 'the edge was asked exactly that: ' . json_encode($requests(), JSON_UNESCAPED_SLASHES));
    check(!method_exists($v, 'hosts') && !method_exists($v, 'send'), 'an edge vault has no hosts or send');
});

// every way an edge can fail is an error naming why, and the token is never in it
foreach ([
    [[200, 'not json'], '~did not answer with JSON \(200\)~'],
    [[502, '<html>bad gateway</html>'], '~did not answer with JSON \(502\)~'],
    [[200, '[1]'], '~did not answer with an object~'],
    [[200, json_encode(['values' => []])], '~no value for~'],
    [[200, json_encode(['values' => [7]])], '~no value for~'],
    [[401, json_encode(['error' => 'revoked', 'message' => 'this token was revoked'])], '~harar refused .*: revoked: this token was revoked~'],
    [[500, '{}'], '~harar refused .*: 500~'],
    [[200, str_repeat('x', 1024 * 1024 + 1)], '~too long an answer~'],
] as [$reply, $why]) {
    edge($reply, function (string $url) use ($why) {
        $e = refuses(fn () => vault(edge: $url, token: TOKEN)->secrets->resolve('harar://a/b'), HararError::class, $why);
        check(!str_contains($e->getMessage(), substr(TOKEN, 28)), 'the token stays out of errors');
    });
}
refuses(fn () => vault(edge: 'http://127.0.0.1:1', token: TOKEN)->secrets->resolve('harar://a/b'), HararError::class, '~^harar at http://127.0.0.1:1: ~');

// an edge is https (or this machine), its token a harar edge token, and it is one or the other
refuses(fn () => vault(edge: 'http://edge.example', token: TOKEN), InvalidArgumentException::class, '~the edge is an https:// URL~');
refuses(fn () => vault(edge: 'http://localhost.evil.example', token: TOKEN), InvalidArgumentException::class, '~the edge is an https:// URL~');
refuses(fn () => vault(edge: 'https://edge.example'), InvalidArgumentException::class, '~service token~');
$e = refuses(fn () => vault(edge: 'https://edge.example', token: 'sk_live_oops'), InvalidArgumentException::class, '~service token~');
check(!str_contains($e->getMessage(), 'sk_live_oops'), 'a wrong token stays out of the error');
refuses(fn () => vault(socket: '/run/harar.sock', edge: 'https://edge.example', token: TOKEN), InvalidArgumentException::class, '~a socket or an edge, not both~');
check(vault(edge: 'https://harar-edge.you.workers.dev', token: TOKEN) instanceof EdgeVault, 'https');
check(vault(edge: 'http://localhost:8787', token: TOKEN) instanceof EdgeVault, 'this machine');

echo "edge_test.php: ok\n";
