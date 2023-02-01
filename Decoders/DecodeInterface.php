<?php

declare(strict_types=1);

namespace SimpleJWT;

/**
 * Interface for Decode classes if customisation is required.
 */
interface DecodeInterface
{
    /**
     * Decode a base64URL string to an associative array.
     *
     * @param string $toDecode
     * @return array
     */
    public function decode(string $toDecode): array;
}
