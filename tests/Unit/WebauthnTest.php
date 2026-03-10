<?php

namespace Xefi\LaravelPasskey\Tests\Unit\Webauthn;

use PHPUnit\Framework\TestCase;
use Xefi\LaravelPasskey\Webauthn\WebAuthn;
use Xefi\LaravelPasskey\Exceptions\MalformedClientDataException;

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

        if (!function_exists('config')) {
            function config($key = null, $default = null)
            {
                if ($key === 'passkey.timeout') {
                    return 600000;
                }
                if ($key === 'passkey.challenge_length') {
                    return 32;
                }
                return $default;
            }
        }
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
        $options = $this->webAuthn->generate_verify_options($challenge, $credentialId);

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
        $this->webAuthn->validate_client_data($clientData, 'webauthn.create');

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
        $this->webAuthn->validate_client_data($clientData, 'webauthn.create');
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
        $this->webAuthn->validate_client_data($clientData, 'webauthn.create');
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
        $result = $this->webAuthn->get_challenge_from_client_data_json($clientDataJson);

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
        $result = $this->webAuthn->parse_auth_data($authData);

        // Assert
        $this->assertEquals($expected['rp_id_hash'], $result['rp_id_hash']);
        $this->assertEquals($expected['flags'], $result['flags']);
        $this->assertEquals($expected['sign_count'], $result['sign_count']);
        $this->assertEquals($expected['aaguid'], $result['aaguid']);
        $this->assertEquals($expected['credential_id'], $result['credential_id']);
        $this->assertEquals($expected['public_key_cbor'], $result['public_key_cbor']);
    }
}
