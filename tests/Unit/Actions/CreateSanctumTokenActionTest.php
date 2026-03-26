<?php

namespace Xefi\LaravelPasskey\Tests\Unit\Actions;

use Illuminate\Http\Request;
use Xefi\LaravelPasskey\Actions\CreateSanctumTokenAction;
use Xefi\LaravelPasskey\Exceptions\UserNotFoundException;
use Xefi\LaravelPasskey\Models\Passkey;
use Xefi\LaravelPasskey\Tests\TestCase;

class CreateSanctumTokenActionTest extends TestCase
{
    private function makeUser(): object
    {
        return new class {
            public int $id = 1;
            public string $name = 'Test User';
            public string $email = 'test@example.com';

            public function createToken(string $name): object
            {
                return new class {
                    public string $plainTextToken = 'sanctum-token-123';
                };
            }
        };
    }

    public function test_returns_json_with_user_and_token(): void
    {
        // Arrange
        $passkey = new Passkey();
        $passkey->setRelation('passkeeable', $this->makeUser());
        $request = Request::create('/api/passkeys/login', 'POST');

        // Act
        $response = (new CreateSanctumTokenAction())($passkey, $request);

        // Assert
        $data = $response->getData(true);
        $this->assertEquals(1, $data['user']['id']);
        $this->assertEquals('Test User', $data['user']['name']);
        $this->assertEquals('test@example.com', $data['user']['email']);
        $this->assertEquals('sanctum-token-123', $data['token']);
    }

    public function test_user_fields_are_nullable_in_response(): void
    {
        // Arrange
        $user = new class {
            public int $id = 2;
            public ?string $name = null;
            public ?string $email = null;

            public function createToken(string $name): object
            {
                return new class {
                    public string $plainTextToken = 'token-abc';
                };
            }
        };

        $passkey = new Passkey();
        $passkey->setRelation('passkeeable', $user);
        $request = Request::create('/api/passkeys/login', 'POST');

        // Act
        $response = (new CreateSanctumTokenAction())($passkey, $request);

        // Assert
        $data = $response->getData(true);
        $this->assertNull($data['user']['name']);
        $this->assertNull($data['user']['email']);
        $this->assertEquals('token-abc', $data['token']);
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
        (new CreateSanctumTokenAction())($passkey, $request);
    }
}
