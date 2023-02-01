<?php

declare(strict_types=1);

namespace SimpleJWT;

/**
 * Interface for Secret classes, enables custom secret validation.
 */
interface SecretValidatorInterface
{
    /**
     * Validate the provided signature secret.
     *
     * @see SecretValidator::validate()
     */
    public function validate(string $secret): bool;
}
