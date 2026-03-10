<?php

namespace Xefi\LaravelPasskey\Tests\Unit\Support;

use PHPUnit\Framework\TestCase;

use Xefi\LaravelPasskey\Support\Utils;

class UtilsTest extends TestCase
{
    /**
     * Test convert_base64url_to_base64 method.
     *
     * @return void
     */
    public function test_can_convert_base64url_to_base64()
    {
        // Arrange
        $base64url = 'a-b_c';
        $expected = 'a+b/c===';

        // Act
        $result = Utils::convert_base64url_to_base64($base64url);

        // Assert
        $this->assertEquals($expected, $result);
    }

    /**
     * Test decode_base64_url method.
     *
     * @return void
     */
    public function test_can_decode_base64url()
    {
        // Arrange
        $base64url = 'aGVsbG8gd29ybGQ';
        $expected = 'hello world';

        // Act
        $result = Utils::decode_base64_url($base64url);

        // Assert
        $this->assertEquals($expected, $result);
    }

    /**
     * Test generate_challenge method.
     *
     * @return void
     */
    public function test_can_generate_challenge()
    {
        // Arrange
        if (!function_exists('config')) {
            function config($key = null, $default = null)
            {
                if ($key === 'passkey.timeout') {
                    return 600000;
                }
                if ($key === 'passkey.challenge_length') {
                    return 32;
                }
                return $default ?? 32;
            }
        }

        // Act
        $challenge = Utils::generate_challenge();

        // Assert
        $this->assertEquals(43, strlen($challenge));
        $this->assertDoesNotMatchRegularExpression('/[\+\/=]/', $challenge);
    }
}
