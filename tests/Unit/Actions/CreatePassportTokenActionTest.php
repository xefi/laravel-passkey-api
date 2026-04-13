<?php

namespace Xefi\LaravelPasskey\Tests\Unit\Actions;

use Illuminate\Http\Request;

use Xefi\LaravelPasskey\Models\Passkey;
use Xefi\LaravelPasskey\Tests\TestCase;
use Xefi\LaravelPasskey\Exceptions\UserNotFoundException;
use Xefi\LaravelPasskey\Actions\CreatePassportTokenAction;

class CreatePassportTokenActionTest extends TestCase
{
    private function makeUser(?string $expiresAt = '2030-01-01 00:00:00'): object
    {
        return new class($expiresAt) {
            public int $id = 1;
            public string $name = 'Test User';
            public string $email = 'test@example.com';

            private ?string $expiresAt;

            public function __construct(?string $expiresAt)
            {
                $this->expiresAt = $expiresAt;
            }

            public function createToken(string $name): object
            {
                $expiresAt = $this->expiresAt;

                return new class($expiresAt) {
                    public string $accessToken = 'passport-access-token-xyz';
                    public object $token;

                    public function __construct(?string $expiresAt)
                    {
                        $this->token = (object) ['expires_at' => $expiresAt];
                    }
                };
            }

            public function getPasskeyDisplayName(): string { return $this->name; }
            public function getPasskeyEmail(): string { return $this->email; }
            public function getKey(): mixed { return $this->id; }
        };
    }

    public function test_returns_json_with_user_and_access_token(): void
    {
        // Arrange
        $passkey = new Passkey();
        $passkey->setRelation('passkeeable', $this->makeUser('2030-01-01 00:00:00'));
        $request = Request::create('/api/passkeys/login', 'POST');

        // Act
        $response = (new CreatePassportTokenAction())($passkey, $request);

        // Assert
        $data = $response->getData(true);
        $this->assertEquals(1, $data['user']['id']);
        $this->assertEquals('Test User', $data['user']['name']);
        $this->assertEquals('test@example.com', $data['user']['email']);
        $this->assertEquals('passport-access-token-xyz', $data['token']);
        $this->assertEquals('2030-01-01 00:00:00', $data['expires_at']);
    }

    public function test_returns_null_expires_at_when_token_does_not_expire(): void
    {
        // Arrange
        $passkey = new Passkey();
        $passkey->setRelation('passkeeable', $this->makeUser(null));
        $request = Request::create('/api/passkeys/login', 'POST');

        // Act
        $response = (new CreatePassportTokenAction())($passkey, $request);

        // Assert
        $data = $response->getData(true);
        $this->assertNull($data['expires_at']);
    }

    public function test_throws_user_not_found_when_passkeeable_is_null(): void
    {
        // Arrange
        $passkey = new Passkey();
        $passkey->setRelation('passkeeable', null);
        $request = Request::create('/api/passkeys/login', 'POST');

        // Assert
        $this->expectException(UserNotFoundException::class);

        // Act
        (new CreatePassportTokenAction())($passkey, $request);
    }
}
