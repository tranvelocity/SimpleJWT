<?php

declare(strict_types=1);

namespace SimpleJWT;

/**
 * A simple class for creating JSON Web Tokens that uses HMAC SHA256 to sign
 * signatures.
 *
 * For more information on JSON Web Tokens please see https://jwt.io
 * along with the RFC https://tools.ietf.org/html/rfc7519
 */
class JwtAuth
{
    /**
     * @param array $payload
     * @param string $secret
     * @return string
     * @throws Exceptions\JwtBuilderException
     * @throws Exceptions\TokenException
     */
    public static function generate(array $payload, string $secret): string
    {
        return (new JwtFactory())->generate($payload, $secret)->getToken();
    }

    /**
     * @param string $token
     * @param string $secret
     * @return bool
     */
    public static function validate(string $token, string $secret): bool
    {
        return (new JwtFactory())->validate($token, $secret);
    }

    /**
     * @param string $token
     * @param string $secret
     * @return array
     */
    public static function getPayload(string $token, string $secret): array
    {
        return (new JwtFactory())->getPayload($token, $secret);
    }
}
