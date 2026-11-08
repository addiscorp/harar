<?php

// A stand-in harar edge for edge_test.php: an HTTP/1.1 server on a free
// port, mounted under /functions/v1/harar-edge as on Supabase. It prints the
// port, appends each request to argv[1] (one JSON line each), and answers
// with argv[2]'s status and body, or as an edge would for a Stripe key when
// argv[2] is "stripe".

declare(strict_types=1);

[, $log, $reply] = $argv;
$server = stream_socket_server('tcp://127.0.0.1:0', $code, $message);
if ($server === false) {
    fwrite(STDERR, "edge stand-in: {$message}\n");
    exit(1);
}
$fixed = $reply === 'stripe' ? null : json_decode(file_get_contents($reply), true);
$values = ['harar://prod/shop/STRIPE_KEY' => 'sk_live_real', 'harar://prod/shop/OTHER' => 'other'];
fwrite(STDOUT, explode(':', stream_socket_get_name($server, false))[1] . "\n");
while ($conn = @stream_socket_accept($server, -1)) {
    [$method, $path] = explode(' ', trim((string) fgets($conn)));
    $headers = [];
    while (($line = fgets($conn)) !== false && $line !== "\r\n") {
        [$name, $value] = explode(':', $line, 2);
        $headers[strtolower($name)] = trim($value);
    }
    $length = (int) ($headers['content-length'] ?? 0);
    $raw = '';
    while (strlen($raw) < $length && !feof($conn)) {
        $raw .= fread($conn, $length - strlen($raw));
    }
    $body = json_decode($raw, true);
    file_put_contents($log, json_encode([
        'method' => $method,
        'url' => $path,
        'auth' => $headers['authorization'] ?? null,
        'type' => $headers['content-type'] ?? null,
        'body' => $body,
    ], JSON_UNESCAPED_SLASHES) . "\n", FILE_APPEND);
    if ($fixed !== null) {
        [$status, $text] = $fixed;
    } elseif (array_diff($body['refs'], array_keys($values)) === []) {
        [$status, $text] = [200, json_encode(['values' => array_map(fn ($r) => $values[$r], $body['refs'])])];
    } else {
        [$status, $text] = [403, json_encode(['error' => 'not_allowed', 'message' => 'this caller may not read prod/site/DATABASE_URL'])];
    }
    @fwrite($conn, "HTTP/1.1 {$status} X\r\ncontent-type: application/json\r\ncontent-length: " . strlen($text) . "\r\nconnection: close\r\n\r\n{$text}");
    fclose($conn);
}
