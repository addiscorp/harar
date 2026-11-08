<?php

// The client against a stand-in harar on a unix socket: the requests it
// sends are the ones harar's `hosts` and `send` take (the harar crate's
// PrimaryRequest::Hosts { key } and Send { key, host }, tag "op"), and every
// way harar can say no is an error naming why. The same cases as js/test.
// Run: php php/tests/vault_test.php (exits non-zero on the first failure).

declare(strict_types=1);

require __DIR__ . '/../src/HararError.php';
require __DIR__ . '/../src/Secrets.php';
require __DIR__ . '/../src/Vault.php';
require __DIR__ . '/../src/functions.php';

use Harar\HararError;
use function Harar\agent_socket;
use function Harar\vault;

function check(bool $ok, string $what): void
{
    if (!$ok) {
        throw new LogicException("failed: {$what}");
    }
}

function refuses(callable $f, string $class, string $why): void
{
    try {
        $f();
    } catch (Throwable $e) {
        check($e instanceof $class, "{$class}, got " . $e::class . ': ' . $e->getMessage());
        check(preg_match($why, $e->getMessage()) === 1, "'{$e->getMessage()}' matches {$why}");
        return;
    }
    check(false, "an error matching {$why}");
}

/** Runs $test against a stand-in harar answering with $reply ("stripe", or a literal answer). */
function harar(string $reply, callable $test): void
{
    $dir = sys_get_temp_dir() . '/harar-php-' . bin2hex(random_bytes(4));
    mkdir($dir, 0700);
    $socket = "{$dir}/h.sock";
    $log = "{$dir}/requests";
    $answer = "{$dir}/answer";
    file_put_contents($answer, $reply);
    touch($log);
    $proc = proc_open(
        [PHP_BINARY, __DIR__ . '/stand-in.php', $socket, $log, $reply === 'stripe' ? 'stripe' : $answer],
        [1 => ['pipe', 'w'], 2 => STDERR],
        $pipes,
    );
    try {
        check(fgets($pipes[1]) === "ready\n", 'the stand-in started');
        $test($socket, fn () => array_map(
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

// hosts and send ask harar exactly, and a send is for one host
harar('stripe', function (string $socket, callable $requests) {
    $v = vault(socket: $socket);
    check($v->hosts('prod/shop/STRIPE_KEY') === ['api.stripe.com', '*.stripe.com'], 'hosts');
    check($v->send('prod/shop/STRIPE_KEY', 'api.stripe.com') === 'sk_live_real', 'send');
    refuses(
        fn () => $v->send('prod/shop/STRIPE_KEY', 'evil.example.com'),
        HararError::class,
        '~harar refused prod/shop/STRIPE_KEY to evil\.example\.com: not_allowed~',
    );
    check($requests() === [
        ['op' => 'hosts', 'key' => 'prod/shop/STRIPE_KEY'],
        ['op' => 'send', 'key' => 'prod/shop/STRIPE_KEY', 'host' => 'api.stripe.com'],
        ['op' => 'send', 'key' => 'prod/shop/STRIPE_KEY', 'host' => 'evil.example.com'],
    ], 'the requests harar saw');
});

// every way harar can fail is an error naming why
foreach ([
    ['not json', '~did not answer with JSON~'],
    ['null', '~did not answer with an object~'],
    ['[1]', '~did not answer with an object~'],
    ['{"ok":true}', '~no value|no hosts~'],
    ['{"ok":true,"hosts":{"a":"x"}}', '~no hosts|no value~'],
    ['{"ok":false,"error":"locked"}', '~harar refused .*: locked~'],
    [str_repeat('x', 1024 * 1024 + 1), '~too long an answer~'],
] as [$answer, $why]) {
    harar($answer, function (string $socket) use ($why) {
        $v = vault(socket: $socket);
        refuses(fn () => $v->send('a/b', 'x.example.com'), HararError::class, $why);
        refuses(fn () => $v->hosts('a/b'), HararError::class, $why);
    });
}
refuses(fn () => vault(socket: '/nonexistent/h.sock')->hosts('a/b'), HararError::class, '~harar at /nonexistent/h\.sock~');
refuses(fn () => vault(socket: 'relative.sock'), InvalidArgumentException::class, '~absolute path~');

// secrets->resolve reads the key a harar:// reference names, as op:// does in 1Password
harar('{"ok":true,"value":"sk_live_real"}', function (string $socket, callable $requests) {
    $v = vault(socket: $socket);
    check($v->secrets->resolve('harar://prod/shop/STRIPE_KEY') === 'sk_live_real', 'resolve');
    check($v->secrets->resolveAll(['harar://prod/shop/STRIPE_KEY', 'harar://prod/shop/OTHER']) === ['sk_live_real', 'sk_live_real'], 'resolveAll');
    // Not a reference: refused before harar is asked anything.
    foreach (['prod/shop/STRIPE_KEY', 'op://Prod/Stripe/credential', 'harar://', 'harar://a b'] as $notOne) {
        refuses(fn () => $v->secrets->resolve($notOne), HararError::class, '~not a harar:// reference~');
    }
    check($requests() === [
        ['op' => 'get', 'key' => 'prod/shop/STRIPE_KEY'],
        ['op' => 'get', 'key' => 'prod/shop/STRIPE_KEY'],
        ['op' => 'get', 'key' => 'prod/shop/OTHER'],
    ], 'the requests harar saw');
});
harar('{"ok":false,"error":"not_found"}', function (string $socket) {
    refuses(fn () => vault(socket: $socket)->secrets->resolve('harar://prod/shop/GONE'), HararError::class, '~harar refused harar://prod/shop/GONE: not_found~');
});

// vault() with no socket asks the agent where `harar agent` listens
$saved = ['HOME' => getenv('HOME'), 'XDG_RUNTIME_DIR' => getenv('XDG_RUNTIME_DIR')];
putenv('HOME=/home/someone');
putenv('XDG_RUNTIME_DIR=/run/user/1000');
$want = PHP_OS_FAMILY === 'Darwin' ? '/home/someone/Library/Application Support/harar/agent.sock' : '/run/user/1000/harar/agent.sock';
check(agent_socket() === $want, "agent_socket() is {$want}");
refuses(fn () => vault()->secrets->resolve('harar://a/b'), HararError::class, '~^harar at ' . preg_quote($want, '~') . ':~');
putenv('XDG_RUNTIME_DIR');
if (PHP_OS_FAMILY !== 'Darwin') {
    check(agent_socket() === '/home/someone/.harar/agent.sock', 'agent_socket() falls back to ~/.harar');
}
foreach ($saved as $name => $value) {
    putenv($value === false ? $name : "{$name}={$value}");
}

echo "ok: php client\n";
