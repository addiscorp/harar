<?php

declare(strict_types=1);

namespace Harar;

/**
 * harar:// references resolved at a harar edge (docs/edge.md), with a
 * service token: one POST of /v1/resolve, all or nothing.
 */
final class EdgeSecrets
{
    public function __construct(private readonly string $edge, private readonly string $token)
    {
    }

    /** The value `$ref` names. */
    public function resolve(string $ref): string
    {
        return $this->resolveAll([$ref])[0];
    }

    /**
     * Each reference's value, in order, in one request: all or nothing.
     *
     * @param list<string> $refs
     * @return list<string>
     */
    public function resolveAll(array $refs): array
    {
        if ($refs === []) {
            return [];
        }
        foreach ($refs as $ref) {
            if (!is_string($ref) || reference($ref) === null) {
                throw new HararError('not a harar:// reference: ' . json_encode($ref, JSON_UNESCAPED_SLASHES));
            }
        }
        $refs = array_values($refs);
        $what = count($refs) === 1 ? $refs[0] : count($refs) . ' references';
        [$status, $body] = $this->post(json_encode(['refs' => $refs], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
        $answer = json_decode($body, true);
        if ($answer === null && json_last_error() !== JSON_ERROR_NONE) {
            throw new HararError("harar at {$this->edge} did not answer with JSON ({$status})");
        }
        if (!is_array($answer) || array_is_list($answer) && $answer !== []) {
            throw new HararError("harar at {$this->edge} did not answer with an object");
        }
        if ($status < 200 || $status > 299) {
            $code = is_string($answer['error'] ?? null) ? $answer['error'] : (string) $status;
            $message = is_string($answer['message'] ?? null) ? ": {$answer['message']}" : '';
            throw new HararError("harar refused {$what}: {$code}{$message}");
        }
        $values = $answer['values'] ?? null;
        if (!is_array($values) || !array_is_list($values) || count($values) !== count($refs) || array_filter($values, 'is_string') !== $values) {
            throw new HararError("harar sent no value for {$what}");
        }
        return $values;
    }

    /** @return array{int, string} the status and the body, refused past MAX_ANSWER bytes */
    private function post(string $body): array
    {
        $context = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => "content-type: application/json\r\nauthorization: Bearer {$this->token}\r\n",
                'content' => $body,
                'timeout' => Vault::TIMEOUT_S,
                'ignore_errors' => true,
                'protocol_version' => 1.1,
            ],
        ]);
        $error = null;
        set_error_handler(function (int $_, string $message) use (&$error): bool {
            $error = preg_replace('/^.*?: /', '', $message);
            return true;
        });
        try {
            $stream = fopen("{$this->edge}/v1/resolve", 'rb', false, $context);
        } finally {
            restore_error_handler();
        }
        if ($stream === false) {
            throw new HararError("harar at {$this->edge}: " . ($error ?? 'unreachable'));
        }
        try {
            $text = '';
            while (!feof($stream)) {
                $chunk = fread($stream, 65536);
                if ($chunk === false) {
                    break;
                }
                $text .= $chunk;
                if (strlen($text) > Vault::MAX_ANSWER) {
                    throw new HararError('harar sent too long an answer');
                }
            }
            if (stream_get_meta_data($stream)['timed_out']) {
                throw new HararError("harar at {$this->edge}: did not answer in " . Vault::TIMEOUT_S . ' s');
            }
            $headers = stream_get_meta_data($stream)['wrapper_data'] ?? [];
            $status = 0;
            foreach ($headers as $line) {
                if (is_string($line) && preg_match('~^HTTP/\S+ (\d{3})~', $line, $m) === 1) {
                    $status = (int) $m[1];
                }
            }
            return [$status, $text];
        } finally {
            fclose($stream);
        }
    }
}
