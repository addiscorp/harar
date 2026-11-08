<?php

// harar's client for PHP:
//
//   $harar = Harar\vault();                                // the agent on this machine
//   $harar->secrets->resolve('harar://prod/shop/STRIPE_KEY'); // the key it names
//
// A gateway that attaches keys on their way out asks where each may go, and
// for it for one host only: hosts($secret) and send($secret, $host).
//
// One JSON request on harar's local socket, the write side closed, one JSON
// answer: the protocol the per-user agent and a primary both speak. harar
// decides every send, and records the host; this client holds nothing.

declare(strict_types=1);

namespace Harar;

/**
 * A vault on harar's socket: the secrets its references name, and for a
 * gateway, where each may go and the secret itself for one host only.
 */
final class Vault
{
    /** harar's answers are small; anything longer is refused. */
    public const MAX_ANSWER = 1024 * 1024;
    /** How long harar has to answer (a per-user agent may be asking for Touch ID). */
    public const TIMEOUT_S = 60;

    public readonly Secrets $secrets;

    public function __construct(private readonly string $socket)
    {
        if (!str_starts_with($socket, '/')) {
            throw new \InvalidArgumentException('Harar\vault(socket:): the socket is an absolute path');
        }
        $this->secrets = new Secrets($this->ask(...));
    }

    /**
     * For a gateway: the host patterns `$secret` may go to: an exact name, or `*.example.com`
     * for any name under it (never the name itself).
     *
     * @return list<string>
     */
    public function hosts(string $secret): array
    {
        $hosts = $this->ask(['op' => 'hosts', 'key' => $secret], $secret)['hosts'] ?? null;
        if (!is_array($hosts) || !array_is_list($hosts) || array_filter($hosts, 'is_string') !== $hosts) {
            throw new HararError("harar sent no hosts for {$secret}");
        }
        return $hosts;
    }

    /** For a gateway: `$secret`'s value, for a request to `$host` only. */
    public function send(string $secret, string $host): string
    {
        $value = $this->ask(['op' => 'send', 'key' => $secret, 'host' => $host], "{$secret} to {$host}")['value'] ?? null;
        if (!is_string($value)) {
            throw new HararError("harar refused {$secret} to {$host}: no value");
        }
        return $value;
    }

    /**
     * One request to harar, and its answer if it says ok; otherwise why not.
     *
     * @param array<string, string> $request
     * @return array<mixed>
     */
    private function ask(array $request, string $what): array
    {
        $body = $this->exchange(json_encode($request, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
        try {
            $answer = json_decode($body, false, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            throw new HararError("harar at {$this->socket} did not answer with JSON");
        }
        if (!$answer instanceof \stdClass) {
            throw new HararError("harar at {$this->socket} did not answer with an object");
        }
        $answer = (array) $answer;
        if (($answer['ok'] ?? null) === true) {
            return $answer;
        }
        $error = $answer['error'] ?? null;
        throw new HararError("harar refused {$what}: " . (is_string($error) ? $error : 'no answer'));
    }

    private function exchange(string $request): string
    {
        $conn = @stream_socket_client("unix://{$this->socket}", $code, $message, self::TIMEOUT_S);
        if ($conn === false) {
            throw new HararError("harar at {$this->socket}: {$message}");
        }
        try {
            stream_set_timeout($conn, self::TIMEOUT_S);
            if (@fwrite($conn, $request) !== strlen($request)) {
                throw new HararError("harar at {$this->socket}: could not send the request");
            }
            stream_socket_shutdown($conn, STREAM_SHUT_WR);
            $body = '';
            while (!feof($conn)) {
                $chunk = fread($conn, 65536);
                if (stream_get_meta_data($conn)['timed_out']) {
                    throw new HararError('harar did not answer in ' . self::TIMEOUT_S . ' s');
                }
                if ($chunk === false) {
                    throw new HararError("harar at {$this->socket}: the answer could not be read");
                }
                $body .= $chunk;
                if (strlen($body) > self::MAX_ANSWER) {
                    throw new HararError('harar sent too long an answer');
                }
            }
            return $body;
        } finally {
            fclose($conn);
        }
    }
}
