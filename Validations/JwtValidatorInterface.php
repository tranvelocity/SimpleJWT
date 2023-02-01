<?php

declare(strict_types=1);

namespace SimpleJWT;

/**
 * Interface for JwtValidator classes to allow developers to implement custom token
 * validation if required.
 */
interface JwtValidatorInterface
{
    /**
     * Confirm the structure of a JSON Web Token.
     *
     * @param string $jwt
     * @return boolean
     */
    public function structure(string $jwt): bool;

    /**
     * Check the validity of the JWT's expiration claim.
     *
     * @param int $expiration
     * @return boolean
     */
    public function expiration(int $expiration): bool;

    /**
     * Check the token signature and generated signature match.
     *
     * @param string $generatedSignature
     * @param string $tokenSignature
     * @return boolean
     */
    public function signature(string $generatedSignature, string $tokenSignature): bool;

    /**
     * Check the alg claim is in the list of valid algorithms.
     *
     * @param string $algorithm
     * @param array $validAlgorithms
     * @return boolean
     */
    public function algorithm(string $algorithm, array $validAlgorithms): bool;
}
