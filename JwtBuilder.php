<?php

declare(strict_types=1);

namespace SimpleJWT;

use SimpleJWT\Exceptions\JwtBuilderException;
use SimpleJWT\Entities\Token;
use SimpleJWT\Encoders\EncodeInterface;
use SimpleJWT\Validations\JwtValidator;
use SimpleJWT\Validations\SecretValidatorInterface;

/**
 * A class to help build a JSON Web Token.
 *
 * Class contains helper methods that allow you to easily set JWT claims
 * defined in the JWT RFC. Eg setIssuer() will set the iss claim in the
 * JWT payload.
 */
class JwtBuilder
{
    /**
     * Defines the type of JWT to be created, usually just JWT.
     */
    private $type;

    /**
     * Holds the JWT header claims
     *
     * @var array
     */
    private $header = [];

    /**
     * Holds the JWT payload claims.
     *
     * @var array
     */
    private $payload = [];

    /**
     * The secret string for encoding the JWT signature.
     */
    private $secret = '';

    /**
     * Token claim validator.
     */
    private $validate;

    /**
     * Signature secret validator.
     */
    private $secretValidator;

    /**
     * Token Encoder which complies with the encoder interface.
     */
    private $encode;

    public function __construct(
        string $type,
        JwtValidator $validate,
        SecretValidatorInterface $secretValidator,
        EncodeInterface $encode
    ) {
        $this->type = $type;
        $this->validate = $validate;
        $this->secretValidator =  $secretValidator;
        $this->encode = $encode;
    }

    /**
     * Define the content type header claim for the JWT. This defines
     * structural information about the token. For instance if it is a
     * nested token.
     */
    public function setContentType(string $contentType): JwtBuilder
    {
        $this->header['cty'] = $contentType;

        return $this;
    }

    /**
     * Add custom claims to the JWT header
     *
     * @param mixed $value
     */
    public function setHeaderClaim(string $key, $value): JwtBuilder
    {
        $this->header[$key] = $value;

        return $this;
    }

    /**
     * Get the contents of the JWT header. This is an associative array of
     * the defined header claims. The JWT algorithm and typ are added
     * by default.
     *
     * @return mixed[]
     */
    public function getHeader(): array
    {
        return array_merge(
            $this->header,
            ['alg' => $this->encode->getAlgorithm(), 'typ' => $this->type]
        );
    }

    /**
     * Set the JWT secret for encrypting the JWT signature. The secret must
     * comply with the validation rules defined in the
     *
     * @param string $secret
     * @throws JwtBuilderException
     */
    public function setSecret(string $secret): JwtBuilder
    {
        if (!$this->secretValidator->validate($secret)) {
            throw new JwtBuilderException('Invalid secret.', 9);
        }

        $this->secret = $secret;

        return $this;
    }

    /**
     * Set the issuer JWT payload claim. This defines who issued the token.
     * Can be a string or URI.
     */
    public function setIssuer(string $issuer): JwtBuilder
    {
        $this->payload['iss'] = $issuer;

        return $this;
    }

    /**
     * Set the subject JWT payload claim. This defines who the JWT is for.
     * Eg an application user or admin.
     */
    public function setSubject(string $subject): JwtBuilder
    {
        $this->payload['sub'] = $subject;

        return $this;
    }

    /**
     * Set the audience JWT payload claim. This defines a list of 'principals'
     * who will process the JWT. Eg a website or websites who will validate
     * users who use this token. This claim can either be a single string or an
     * array of strings.
     *
     * @param mixed $audience
     * @throws JwtBuilderException
     */
    public function setAudience($audience): JwtBuilder
    {
        if (is_string($audience) || is_array($audience)) {
            $this->payload['aud'] = $audience;

            return $this;
        }

        throw new JwtBuilderException('Invalid Audience claim.', 10);
    }

    /**
     * Set the expiration JWT payload claim. This sets the time at which the
     * JWT should expire and no longer be accepted.
     *
     * @throws JwtBuilderException
     */
    public function setExpiration(int $timestamp): JwtBuilder
    {
        if (!$this->validate->expiration($timestamp)) {
            throw new JwtBuilderException('Expiration claim has expired.', 4);
        }

        $this->payload['exp'] = $timestamp;

        return $this;
    }

    /**
     * Set the not before JWT payload claim. This sets the time after which the
     * JWT can be accepted.
     */
    public function setNotBefore(int $notBefore): JwtBuilder
    {
        $this->payload['nbf'] = $notBefore;

        return $this;
    }

    /**
     * Set the issued at JWT payload claim. This sets the time at which the
     * JWT was issued / created.
     */
    public function setIssuedAt(int $issuedAt): JwtBuilder
    {
        $this->payload['iat'] = $issuedAt;

        return $this;
    }

    /**
     * Set the JSON token identifier JWT payload claim. This defines a unique
     * identifier for the token.
     */
    public function setJwtId(string $jwtId): JwtBuilder
    {
        $this->payload['jti'] = $jwtId;

        return $this;
    }

    /**
     * Set a custom payload claim on the JWT. The RFC calls these private
     * claims. Eg you may wish to set a user_id or a username in the
     * JWT payload.
     *
     * @param mixed $value
     */
    public function setPayloadClaim(string $key, $value): JwtBuilder
    {
        $this->payload[$key] = $value;

        return $this;
    }

    /**
     * Get the JWT payload. This will return an array of registered claims and
     * private claims which make up the JWT payload.
     *
     * @return array
     */
    public function getPayload(): array
    {
        return $this->payload;
    }

    /**
     * Build the token, this is the last method which should be called after
     * all the header and payload claims have been set. It will encode the
     * header and payload, and generate the JWT signature. It will then
     * concatenate each part with dots into a single string.
     *
     * This JWT string along with the secret are then used to generate a new
     * instance of the JWT class which is returned.
     * @throws JwtBuilderException
     */
    public function build(): Token
    {
        return new Token(
            $this->encode->encode($this->getHeader()) . "." .
            $this->encode->encode($this->getPayload()) . "." .
            $this->getSignature(),
            $this->secret
        );
    }

    /**
     * Generate a new token with the same initial setup. Allows you to chain the
     * creation of multiple tokens.
     */
    public function reset(): JwtBuilder
    {
        return new Build(
            $this->type,
            $this->validate,
            $this->secretValidator,
            $this->encode
        );
    }

    /**
     * Generate and return the JWT signature, this is made up of the header,
     * payload and secret.
     *
     * @throws JwtBuilderException
     */
    private function getSignature(): string
    {
        if ($this->secretValidator->validate($this->secret)) {
            return $this->encode->signature(
                $this->getHeader(),
                $this->getPayload(),
                $this->secret
            );
        }

        throw new JwtBuilderException('Invalid secret.', 9);
    }
}
