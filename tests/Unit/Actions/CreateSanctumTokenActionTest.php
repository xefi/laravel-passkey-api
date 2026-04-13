<?php

namespace Xefi\LaravelPasskey\Tests\Unit\Actions;

use Illuminate\Http\Request;

use Xefi\LaravelPasskey\Models\Passkey;
use Xefi\LaravelPasskey\Tests\TestCase;
use Xefi\LaravelPasskey\Actions\CreateSanctumTokenAction;
use Xefi\LaravelPasskey\Exceptions\UserNotFoundException;

class CreateSanctumTokenActionTest extends TestCase
{
    private function makeUser(): object
    {
        return new class {
            public int $id = 1;

            public function createToken(string $name): object
            {
                return new class {
                    public string $plainTextToken = 'sanctum-token-123';
                };
            }

            public function getPasskeyDisplayName(): string { return 'Test User'; }
            public function getPasskeyEmail(): string { return 'test@example.com'; }
            public function getKey(): mixed { return $this->id; }
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

    public function test_uses_trait_method_overrides_for_user_fields(): void
    {
        // Arrange — user with custom display name (e.g. Admin with username field)
        $user = new class {
            public int $id = 2;

            public function createToken(string $name): object
            {
                return new class {
                    public string $plainTextToken = 'token-abc';
                };
            }

            public function getPasskeyDisplayName(): string { return 'admin_alice'; }
            public function getPasskeyEmail(): string { return 'alice@admin.example.com'; }
            public function getKey(): mixed { return $this->id; }
        };

        $passkey = new Passkey();
        $passkey->setRelation('passkeeable', $user);
        $request = Request::create('/api/passkeys/login', 'POST');

        // Act
        $response = (new CreateSanctumTokenAction())($passkey, $request);

        // Assert
        $data = $response->getData(true);
        $this->assertEquals('admin_alice', $data['user']['name']);
        $this->assertEquals('alice@admin.example.com', $data['user']['email']);
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
