<?php

declare(strict_types=1);

namespace SimpleJWT;

/**
 * A validation helper class which offers methods to confirm the validity of
 * a JSON Web Token along with aspects of its content.
 */
class JwtValidator implements JwtValidatorInterface
{
    /**
     * Confirm the structure of a JSON Web Token, it has three parts separated
     * by dots and complies with Base64URL standards.
     *
     * @param string $jwt
     * @return bool
     */
    public function structure(string $jwt): bool
    {
        return preg_match(
            '/^[a-zA-Z0-9\-\_\=]+\.[a-zA-Z0-9\-\_\=]+\.[a-zA-Z0-9\-\_\=]+$/',
            $jwt
        ) === 1;
    }

    /**
     * Check the validity of the JWT's expiration claim as defined in the
     * token payload. Returns false if the current time has surpassed the
     * expiration time. Time = 100 and Expiration = 99 token has expired.
     *
     * @param int $expiration
     * @return bool
     */
    public function expiration(int $expiration): bool
    {
        return $expiration > time();
    }

    /**
     * Check two signature hashes match. One signature is supplied by the token.
     * The other is newly generated from the token's header and payload. They
     * should match, if they don't someone has likely tampered with the token.
     *
     * @param string $generatedSignature
     * @param string $tokenSignature
     * @return bool
     */
    public function signature(string $generatedSignature, string $tokenSignature): bool
    {
        return hash_equals($generatedSignature, $tokenSignature);
    }

    /**
     * Check the alg claim is in the list of valid algorithms. These are the
     * valid digital signatures, MAC algorithms or "none" as
     * defined in RFC 7518.
     *
     * @param string $algorithm
     * @param array $validAlgorithms
     * @return bool
     */
    public function algorithm(string $algorithm, array $validAlgorithms): bool
    {
        return in_array($algorithm, $validAlgorithms);
    }
}
