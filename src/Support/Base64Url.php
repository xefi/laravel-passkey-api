<?php

namespace Xefi\LaravelPasskey\Support;

class Base64Url
{
    /**
     * Convert base64url to standard base64 format.
     * 
     * Handles replacing URL-safe characters with standard base64 characters
     * and adding necessary padding for standard base64 strings.
     * 
     * @param string $input Base64url-encoded string
     * @return string Standard base64-encoded string
     */
    public static function toBase64(string $input): string
    {
        return str_pad(
            strtr($input, '-_', '+/'),
            strlen($input) + (4 - strlen($input) % 4) % 4,
            '=',
            STR_PAD_RIGHT
        );
    }

    /**
     * Decode a base64url-encoded string.
     * 
     * Converts base64url encoding (URL-safe, no padding) to standard base64
     * and decodes it to binary data.
     * 
     * @param string $input Base64url-encoded string
     * @return string Decoded binary data
     */
    public static function decode(string $input): string
    {
        $input .= str_repeat('=', (4 - strlen($input) % 4) % 4);
        return base64_decode(strtr($input, '-_', '+/'), true);
    }

    /**
     * Generate a cryptographically secure random challenge.
     * 
     * Creates a base64url-encoded random challenge for use in credential creation
     * and authentication ceremonies.
     * 
     * @return string Base64url-encoded challenge (no padding)
     */
    public static function generateChallenge(): string
    {
        $length = config('passkey.challenge_length', 32);
        return self::encode(random_bytes($length));
    }

    /**
     * Encode binary data to base64url format.
     *
     * @param string $input Binary data
     * @return string Base64url-encoded string (no padding)
     */
    public static function encode(string $input): string
    {
        return rtrim(strtr(base64_encode($input), '+/', '-_'), '=');
    }
}
