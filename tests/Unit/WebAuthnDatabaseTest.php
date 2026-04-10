<?php

namespace Xefi\LaravelPasskey\Tests\Unit\Webauthn;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Xefi\LaravelPasskey\Tests\TestCase;
use Xefi\LaravelPasskey\Webauthn\WebAuthn;
use Xefi\LaravelPasskey\Exceptions\PasskeyNotFoundException;

class WebAuthnDatabaseTest extends TestCase
{
    use RefreshDatabase;

    protected WebAuthn $webAuthn;

    protected function setUp(): void
    {
        parent::setUp();

        $this->webAuthn = new WebAuthn();
    }

    public function test_verify_passkey_throws_when_passkey_not_found(): void
    {
        // Arrange — credential ID that does not exist in the database
        $credentialId = rtrim(strtr(base64_encode('nonexistent-credential'), '+/', '-_'), '=');

        // Assert
        $this->expectException(PasskeyNotFoundException::class);

        // Act
        $this->webAuthn->verifyPasskey($credentialId, [
            'clientDataJSON'    => base64_encode(json_encode([
                'type'      => 'webauthn.get',
                'challenge' => 'dGVzdA',
                'origin'    => 'https://example.com',
            ])),
            'authenticatorData' => rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '='),
            'signature'         => rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '='),
        ]);
    }
}
