<?php

declare(strict_types=1);

namespace SimpleJWT;

use SimpleJWT\Decoders\Decode;
use SimpleJWT\Encoders\EncodeHS256;
use SimpleJWT\Entities\Token;
use SimpleJWT\Entities\Parse;
use SimpleJWT\Exceptions\TokenException;
use SimpleJWT\Exceptions\ValidateException;
use SimpleJWT\Validations\JwtValidator;
use SimpleJWT\Validations\SecretValidator;

/**
 * Core factory and interface class for creating basic JSON Web Tokens.
 */
class JwtFactory
{
    /**
     * Factory method to return an instance of the Build class for creating new
     * JSON Web Tokens.
     */
    public function builder(): JwtBuilder
    {
        return new JwtBuilder(
            'JWT',
            new JwtValidator(),
            new SecretValidator(),
            new EncodeHS256()
        );
    }

    /**
     * Create a basic token based on an array of payload claims.
     * Format [string: mixed].
     *
     * @param array $payload
     * @throws TokenException|Exceptions\JwtBuilderException
     */
    public function generate(array $payload, string $secret): Token
    {
        $builder = $this->builder();

        foreach ($payload as $key => $value) {
            if (is_int($key)) {
                throw new TokenException('Invalid payload claim.', 8);
            }

            $builder->setPayloadClaim($key, $value);
        }

        return $builder->setSecret($secret)->build();
    }


    /**
     * Return the payload claims data from a JWT.
     *
     * @return array
     */
    public function getPayload(string $token, string $secret): array
    {
        $parser = $this->initParser($token, $secret);
        return $parser->parse()->getPayload();
    }

    /**
     * Validate the token structure and signature.
     */
    public function validate(string $token, string $secret): bool
    {
        $validate = $this->validator($token, $secret);

        try {
            $validate->structure()
                ->algorithmNotNone()
                ->signature();
            return true;
        } catch (ValidateException | Exceptions\ParseException $e) {
            return false;
        }
    }

    /**
     * Factory method to return an instance of the JwtValidator class to validate
     * the structure, signature and claims data of a JWT.
     */
    public function validator(string $token, string $secret): Validate
    {
        $parse = $this->initParser($token, $secret);
        return new Validate($parse, new EncodeHS256(), new JwtValidator());
    }

    /**
     * Factory method to return an instance of the Parse class for parsing a JWT
     * and gaining access to the token's header and payload claims data.
     */
    public function initParser(string $token, string $secret): Parse
    {
        return new Parse(
            new Token(
                $token,
                $secret
            ),
            new Decode()
        );
    }
}
