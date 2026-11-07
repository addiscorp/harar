<?php

// A stand-in harar for vault_test.php: listens on argv[1], appends each
// request to argv[2] (one JSON line each), and answers with argv[3]'s
// contents, or as harar would for a Stripe key when argv[3] is "stripe".

declare(strict_types=1);

[, $socket, $log, $reply] = $argv;
$server = stream_socket_server("unix://{$socket}", $code, $message);
if ($server === false) {
    fwrite(STDERR, "stand-in: {$message}\n");
    exit(1);
}
$answer = $reply === 'stripe' ? null : file_get_contents($reply);
fwrite(STDOUT, "ready\n");
while ($conn = @stream_socket_accept($server, -1)) {
    $request = json_decode(stream_get_contents($conn), true, 512, JSON_THROW_ON_ERROR);
    file_put_contents($log, json_encode($request, JSON_UNESCAPED_SLASHES) . "\n", FILE_APPEND);
    $body = $answer ?? match (true) {
        $request['op'] === 'hosts' => json_encode(['ok' => true, 'hosts' => ['api.stripe.com', '*.stripe.com']]),
        $request['op'] === 'send' && $request['host'] === 'api.stripe.com' => json_encode(['ok' => true, 'value' => 'sk_live_real']),
        default => json_encode(['ok' => false, 'error' => 'not_allowed']),
    };
    @fwrite($conn, $body); // a client that stopped reading (too long an answer) is fine
    fclose($conn);
}
