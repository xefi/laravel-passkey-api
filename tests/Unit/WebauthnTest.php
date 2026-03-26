<?php

namespace Xefi\LaravelPasskey\Tests\Unit\Webauthn;

use Xefi\LaravelPasskey\Tests\TestCase;
use Xefi\LaravelPasskey\Webauthn\WebAuthn;
use Xefi\LaravelPasskey\Webauthn\Algorithm;
use Xefi\LaravelPasskey\Exceptions\MalformedClientDataException;
use Xefi\LaravelPasskey\Exceptions\InvalidAttestationFormatException;
use Xefi\LaravelPasskey\Exceptions\MalformedAttestationException;
use Xefi\LaravelPasskey\Exceptions\InvalidCoseKeyException;
use Xefi\LaravelPasskey\Exceptions\UnsupportedAlgorithmException;
use Xefi\LaravelPasskey\Exceptions\InvalidSignatureException;

class WebAuthnTest extends TestCase
{
    /**
     * @var WebAuthn
     */
    protected $webAuthn;

    protected function setUp(): void
    {
        parent::setUp();

        $this->webAuthn = new WebAuthn();

        config(['passkey.timeout' => 600000]);
        config(['passkey.challenge_length' => 32]);
    }

    /**
     * Test generated verify options structure.
     *
     * @return void
     */
    public function test_can_generate_verify_options()
    {
        // Arrange
        $challenge = 'test-challenge';
        $credentialId = 'test-credential-id';
        $expectedAllowCredentials = [
            [
                'id' => 'test-credential-id',
                'type' => 'public-key'
            ]
        ];

        // Act
        $options = $this->webAuthn->generateVerifyOptions($challenge, $credentialId);

        // Assert
        $this->assertEquals($challenge, $options['challenge']);
        $this->assertEquals($expectedAllowCredentials, $options['allowCredentials']);
        $this->assertEquals(600000, $options['timeout']);
        $this->assertEquals('required', $options['userVerification']);
    }

    /**
     * Test valid client data passes validation.
     *
     * @return void
     */
    public function test_can_validate_valid_client_data()
    {
        // Arrange
        $clientData = [
            'type' => 'webauthn.create',
            'challenge' => 'test-challenge',
            'origin' => 'https://example.com'
        ];

        // Act
        $this->webAuthn->validateClientData($clientData, 'webauthn.create');

        // Assert
        $this->assertTrue(true);
    }

    /**
     * Test invalid client data type throws exception.
     *
     * @return void
     */
    public function test_validate_client_data_throws_on_wrong_type()
    {
        // Arrange
        $clientData = [
            'type' => 'webauthn.get',
            'challenge' => 'test-challenge',
            'origin' => 'https://example.com'
        ];

        $this->expectException(MalformedClientDataException::class);

        // Act
        $this->webAuthn->validateClientData($clientData, 'webauthn.create');
    }

    /**
     * Test missing fields in client data throws exception.
     *
     * @return void
     */
    public function test_validate_client_data_throws_on_missing_fields()
    {
        // Arrange
        $clientData = [
            'type' => 'webauthn.create',
        ];

        $this->expectException(MalformedClientDataException::class);

        // Act
        $this->webAuthn->validateClientData($clientData, 'webauthn.create');
    }

    /**
     * Test extracting challenge from client data JSON.
     *
     * @return void
     */
    public function test_can_get_challenge_from_client_data_json()
    {
        // Arrange
        $clientData = [
            'type' => 'webauthn.get',
            'challenge' => 'dGVzdC1jaGFsbGVuZ2UtMTIz',
            'origin' => 'https://example.com'
        ];

        $clientDataJson = base64_encode(json_encode($clientData));
        $expected = 'dGVzdC1jaGFsbGVuZ2UtMTIz';

        // Act
        $result = $this->webAuthn->getChallengeFromClientDataJson($clientDataJson);

        // Assert
        $this->assertEquals($expected, $result);
    }

    /**
     * Test parsing authenticator data.
     *
     * @return void
     */
    public function test_can_parse_auth_data()
    {
        // Arrange
        $rpIdHash = str_repeat('A', 32);
        $flags = chr(0b01000001);
        $signCount = pack("N", 42);
        $aaguid = str_repeat('B', 16);
        $credId = 'test-cred';
        $credIdLength = pack("n", strlen($credId));
        $cbor = 'fake-cbor-data';

        $authData = $rpIdHash . $flags . $signCount . $aaguid . $credIdLength . $credId . $cbor;

        $expected = [
            'rp_id_hash' => $rpIdHash,
            'flags' => 65,
            'sign_count' => 42,
            'aaguid' => $aaguid,
            'credential_id' => $credId,
            'public_key_cbor' => $cbor
        ];

        // Act
        $result = $this->webAuthn->parseAuthData($authData);

        // Assert
        $this->assertEquals($expected['rp_id_hash'], $result['rp_id_hash']);
        $this->assertEquals($expected['flags'], $result['flags']);
        $this->assertEquals($expected['sign_count'], $result['sign_count']);
        $this->assertEquals($expected['aaguid'], $result['aaguid']);
        $this->assertEquals($expected['credential_id'], $result['credential_id']);
        $this->assertEquals($expected['public_key_cbor'], $result['public_key_cbor']);
    }

    public function test_can_generate_register_options(): void
    {
        // Act
        $options = $this->webAuthn->generateRegisterOptions(
            'My App',
            'https://example.com',
            '1',
            'user@example.com',
            'Test User'
        );

        // Assert
        $this->assertArrayHasKey('challenge', $options);
        $this->assertEquals('My App', $options['rp']['name']);
        $this->assertEquals('example.com', $options['rp']['id']);
        $this->assertEquals('user@example.com', $options['user']['name']);
        $this->assertEquals('Test User', $options['user']['displayName']);
        $this->assertCount(2, $options['pubKeyCredParams']);
        $this->assertEquals(Algorithm::ES256->value, $options['pubKeyCredParams'][0]['alg']);
        $this->assertEquals(Algorithm::RS256->value, $options['pubKeyCredParams'][1]['alg']);
        $this->assertEquals(600000, $options['timeout']);
        $this->assertEquals('none', $options['attestation']);
    }

    public function test_get_data_for_register_throws_on_malformed_client_data_json(): void
    {
        // Arrange — invalid JSON (json_decode returns null)
        $clientDataJson = base64_encode('{not-valid-json}');
        $attestationObject = rtrim(strtr(base64_encode('anything'), '+/', '-_'), '=');

        // Assert
        $this->expectException(MalformedClientDataException::class);

        // Act
        $this->webAuthn->getDataForRegister($clientDataJson, $attestationObject);
    }

    public function test_get_data_for_register_throws_on_invalid_attestation_format(): void
    {
        // Arrange — valid client data but attestation is CBOR uint(1), not a map
        $clientDataJson = base64_encode(json_encode([
            'type'      => 'webauthn.create',
            'challenge' => 'dGVzdA',
            'origin'    => 'https://example.com',
        ]));
        // CBOR uint(1) = 0x01 — not a MapObject
        $attestationObject = rtrim(strtr(base64_encode("\x01"), '+/', '-_'), '=');

        // Assert
        $this->expectException(InvalidAttestationFormatException::class);

        // Act
        $this->webAuthn->getDataForRegister($clientDataJson, $attestationObject);
    }

    public function test_get_data_for_register_throws_on_missing_auth_data(): void
    {
        // Arrange — valid client data but attestation is an empty CBOR map {}
        $clientDataJson = base64_encode(json_encode([
            'type'      => 'webauthn.create',
            'challenge' => 'dGVzdA',
            'origin'    => 'https://example.com',
        ]));
        // CBOR empty map {} = 0xa0
        $attestationObject = rtrim(strtr(base64_encode("\xa0"), '+/', '-_'), '=');

        // Assert
        $this->expectException(MalformedAttestationException::class);

        // Act
        $this->webAuthn->getDataForRegister($clientDataJson, $attestationObject);
    }

    public function test_verify_throws_on_malformed_client_data_json(): void
    {
        // Arrange — invalid JSON
        $clientDataJson = base64_encode('{not-valid-json}');
        $authData  = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
        $signature = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
        $publicKey = base64_encode("\x01");

        // Assert
        $this->expectException(MalformedClientDataException::class);

        // Act
        $this->webAuthn->verify($clientDataJson, $authData, $signature, $publicKey);
    }

    public function test_verify_throws_on_invalid_cose_key(): void
    {
        // Arrange — public key decodes to CBOR uint(1), not a map
        $clientDataJson = base64_encode(json_encode([
            'type'      => 'webauthn.get',
            'challenge' => 'dGVzdA',
            'origin'    => 'https://example.com',
        ]));
        $authData  = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
        $signature = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
        // CBOR uint(1) = 0x01
        $publicKey = base64_encode("\x01");

        // Assert
        $this->expectException(InvalidCoseKeyException::class);

        // Act
        $this->webAuthn->verify($clientDataJson, $authData, $signature, $publicKey);
    }

    public function test_verify_throws_on_unsupported_algorithm(): void
    {
        // Arrange — COSE key map with alg = -1 (unsupported)
        $clientDataJson = base64_encode(json_encode([
            'type'      => 'webauthn.get',
            'challenge' => 'dGVzdA',
            'origin'    => 'https://example.com',
        ]));
        $authData  = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
        $signature = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
        // CBOR {1: 2, 3: -1} — kty=EC2, unsupported alg
        $publicKey = base64_encode("\xa2\x01\x02\x03\x20");

        // Assert
        $this->expectException(UnsupportedAlgorithmException::class);

        // Act
        $this->webAuthn->verify($clientDataJson, $authData, $signature, $publicKey);
    }

    public function test_verify_throws_on_invalid_signature(): void
    {
        // Arrange — real EC key pair, but signature is over wrong data
        $ecKey   = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        $details = openssl_pkey_get_details($ecKey);
        $x       = $details['ec']['x'];
        $y       = $details['ec']['y'];

        // Manual CBOR encoding of {1:2, 3:-7, -2:x, -3:y}
        // map(4)=0xa4, kty 1:2=0x01 0x02, alg 3:-7=0x03 0x26,
        // -2:bytes(32)=0x21 0x58 0x20 + x, -3:bytes(32)=0x22 0x58 0x20 + y
        $cborKey   = "\xa4\x01\x02\x03\x26\x21\x58\x20" . $x . "\x22\x58\x20" . $y;
        $publicKey = base64_encode($cborKey);

        $clientDataJson = base64_encode(json_encode([
            'type'      => 'webauthn.get',
            'challenge' => 'dGVzdA',
            'origin'    => 'https://example.com',
        ]));
        $authData = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');

        // Sign unrelated data — signature will not match the expected signed_data
        openssl_sign('wrong-data', $rawSig, $ecKey, OPENSSL_ALGO_SHA256);
        $signature = rtrim(strtr(base64_encode($rawSig), '+/', '-_'), '=');

        // Assert
        $this->expectException(InvalidSignatureException::class);

        // Act
        $this->webAuthn->verify($clientDataJson, $authData, $signature, $publicKey);
    }

    public function test_get_challenge_from_client_data_json_throws_on_malformed_json(): void
    {
        // Arrange — base64 of invalid JSON
        $clientDataJson = base64_encode('{not-valid-json}');

        // Assert
        $this->expectException(MalformedClientDataException::class);

        // Act
        $this->webAuthn->getChallengeFromClientDataJson($clientDataJson);
    }
}
