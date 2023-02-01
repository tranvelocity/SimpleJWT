<?php


declare(strict_types=1);

namespace SimpleJWT;

/**
 * Validate the secret used to secure the token signature is strong enough.
 *
 * You can define your own secret validation by creating a new class and
 * implementing the Secret interface.
 */
class SecretValidator implements SecretValidatorInterface
{
    //@TODO This time we will use API secret to make secret to issue JWT.
    //However, since all current API secrets do not include special characters,
    //we will use the pattern without special characters this time,
    //but to enhance security in the future, we should use the pattern including special characters.

    //private const SECRET_PATTERN = '/^.*(?=.{12,}+)(?=.*[0-9]+)(?=.*[A-Z]+)(?=.*[a-z]+)(?=.*[\*&!@%\^#\$]+).*$/';
    private const SECRET_PATTERN = '/^.*(?=.{12,}+)(?=.*[0-9]+)(?=.*[A-Z]+)(?=.*[a-z]+).*$/';

    /**
     * The secret should contain a number, a upper and a lowercase letter, and a
     * special character *&!@%^#$. It should be at least 12 characters in
     * length. The regex here uses lookahead assertions.
     *
     * @param string $secret
     */
    public function validate(string $secret): bool
    {
        return !!preg_match(self::SECRET_PATTERN, $secret);
    }
}
