<?php

declare(strict_types=1);

namespace SimpleJWT;

use SimpleJWT\Traits\Base64;
use SimpleJWT\Traits\JsonEnDecoder;

/**
 * Class to decode a JWT header or payload from a Base64Url string to an
 * associative array.
 */
class Decode implements DecodeInterface
{
    use Base64;
    use JsonEnDecoder;

    /**
     * Decode a Base64 Url string to a json string
     *
     * @param string $toDecode
     * @return string
     */
    private function urlDecode(string $toDecode): string
    {
        return (string) base64_decode(
            $this->addPadding($this->toBase64($toDecode)),
            true
        );
    }

    /**
     * Decode a JSON string to an associative array.
     *
     * @param string $toDecode
     * @return array
     */
    public function decode(string $toDecode): array
    {
        return $this->jsonDecode($this->urlDecode($toDecode));
    }
}
