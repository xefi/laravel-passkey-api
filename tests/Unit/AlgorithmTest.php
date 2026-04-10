<?php

namespace Xefi\LaravelPasskey\Tests\Unit\Webauthn;

use Xefi\LaravelPasskey\Tests\TestCase;
use Xefi\LaravelPasskey\Webauthn\Algorithm;
use Xefi\LaravelPasskey\Exceptions\MissingEcCoordinatesException;
use Xefi\LaravelPasskey\Exceptions\MissingRsaParametersException;

class AlgorithmTest extends TestCase
{
    public function test_es256_has_value_minus_7(): void
    {
        $this->assertSame(-7, Algorithm::ES256->value);
    }

    public function test_rs256_has_value_minus_257(): void
    {
        $this->assertSame(-257, Algorithm::RS256->value);
    }

    public function test_try_from_returns_null_for_unknown_algorithm(): void
    {
        $this->assertNull(Algorithm::tryFrom(-1));
        $this->assertNull(Algorithm::tryFrom(0));
        $this->assertNull(Algorithm::tryFrom(99));
    }

    public function test_es256_build_pem_returns_pem_and_openssl_algo(): void
    {
        // Arrange
        $ecKey = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        $details = openssl_pkey_get_details($ecKey);

        $coseKey = \Cose\Key\Key::create([
            1  => 2,   // kty = EC2
            3  => -7,  // alg = ES256
            -2 => $details['ec']['x'],
            -3 => $details['ec']['y'],
        ]);

        // Act
        $result = Algorithm::ES256->buildPem($coseKey);

        // Assert
        $this->assertIsArray($result);
        $this->assertArrayHasKey('pem', $result);
        $this->assertArrayHasKey('opensslAlgo', $result);
        $this->assertStringContainsString('-----BEGIN PUBLIC KEY-----', $result['pem']);
        $this->assertStringContainsString('-----END PUBLIC KEY-----', $result['pem']);
        $this->assertEquals(OPENSSL_ALGO_SHA256, $result['opensslAlgo']);
    }

    public function test_es256_build_pem_throws_when_coordinates_missing(): void
    {
        // Arrange — COSE key without x/y coordinates
        $coseKey = \Cose\Key\Key::create([1 => 2, 3 => -7]);

        // Assert
        $this->expectException(MissingEcCoordinatesException::class);

        // Act
        Algorithm::ES256->buildPem($coseKey);
    }

    public function test_rs256_build_pem_returns_pem_and_openssl_algo(): void
    {
        // Arrange
        $rsaKey = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $details = openssl_pkey_get_details($rsaKey);

        $coseKey = \Cose\Key\Key::create([
            1  => 3,    // kty = RSA
            3  => -257, // alg = RS256
            -1 => $details['rsa']['n'],
            -2 => $details['rsa']['e'],
        ]);

        // Act
        $result = Algorithm::RS256->buildPem($coseKey);

        // Assert
        $this->assertIsArray($result);
        $this->assertStringContainsString('-----BEGIN PUBLIC KEY-----', $result['pem']);
        $this->assertStringContainsString('-----END PUBLIC KEY-----', $result['pem']);
        $this->assertEquals(OPENSSL_ALGO_SHA256, $result['opensslAlgo']);
    }

    public function test_rs256_build_pem_throws_when_rsa_parameters_missing(): void
    {
        // Arrange — COSE key without modulus/exponent
        $coseKey = \Cose\Key\Key::create([1 => 3, 3 => -257]);

        // Assert
        $this->expectException(MissingRsaParametersException::class);

        // Act
        Algorithm::RS256->buildPem($coseKey);
    }
}
