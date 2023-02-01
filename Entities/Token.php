<?php

declare(strict_types=1);

namespace SimpleJWT;

/**
 * JWT Value object.
 *
 * Consumes a token and a secret string, used when parsing a JWT and generated
 * when creating a JWT.
 */
class Token
{
    /**
     * The JSON Web Token string
     */
    private $token;

    /**
    * The secret used to create the JWT signature
    */
    private $secret;

    /**
     * Token constructor
     *
     * @param string $token
     * @param string $secret
     */
    public function __construct(string $token, string $secret)
    {
        $this->token = $token;
        $this->secret = $secret;
    }

    /**
     * Return the JSON Web Token String
     */
    public function getToken(): string
    {
        return $this->token;
    }

    /**
     * Return the secret used to encode the JWT signature
     */
    public function getSecret(): string
    {
        return $this->secret;
    }
}
