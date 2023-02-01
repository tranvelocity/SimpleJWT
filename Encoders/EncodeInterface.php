<?php

declare(strict_types=1);

namespace SimpleJWT;

/**
 * Interface for Encode classes, enables custom signature encoding dependent
 * on security requirements.
 */
interface EncodeInterface
{
    /**
     * Retrieve the algorithm used to encode the signature.
     */
    public function getAlgorithm(): string;

    /**
     * Encode a JSON string so it is base64URL compliant.
     *
     * @param array $toEncode
     * @return string
     */
    public function encode(array $toEncode): string;

    /**
     * Create the JSON Web Token signature string.
     *
     * @param array $header
     * @param array $payload
     * @param string $secret
     * @return string
     */
    public function signature(array $header, array $payload, string $secret): string;
}
