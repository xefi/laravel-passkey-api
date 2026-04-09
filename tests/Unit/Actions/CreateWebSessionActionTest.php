<?php

namespace Xefi\LaravelPasskey\Tests\Unit\Actions;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Xefi\LaravelPasskey\Actions\CreateWebSessionAction;
use Xefi\LaravelPasskey\Exceptions\UserNotFoundException;
use Xefi\LaravelPasskey\Models\Passkey;
use Xefi\LaravelPasskey\Tests\TestCase;

class CreateWebSessionActionTest extends TestCase
{
    private function makeUser(): Authenticatable
    {
        return new class implements Authenticatable {
            public int $id = 1;
            public string $name = 'Test User';
            public string $email = 'test@example.com';

            public function getAuthIdentifierName(): string { return 'id'; }
            public function getAuthIdentifier(): mixed { return $this->id; }
            public function getAuthPasswordName(): string { return 'password'; }
            public function getAuthPassword(): string { return ''; }
            public function getRememberToken(): ?string { return null; }
            public function setRememberToken($value): void {}
            public function getRememberTokenName(): string { return 'remember_token'; }
            public function getPasskeyDisplayName(): string { return $this->name; }
            public function getPasskeyEmail(): string { return $this->email; }
        };
    }

    public function test_returns_json_with_user_data(): void
    {
        // Arrange
        $passkey = new Passkey();
        $passkey->setRelation('passkeeable', $this->makeUser());
        $request = Request::create('/api/passkeys/login', 'POST');

        // Act
        $response = (new CreateWebSessionAction())($passkey, $request);

        // Assert
        $data = $response->getData(true);
        $this->assertEquals(1, $data['user']['id']);
        $this->assertEquals('Test User', $data['user']['name']);
        $this->assertEquals('test@example.com', $data['user']['email']);
        $this->assertArrayNotHasKey('token', $data);
    }

    public function test_logs_in_the_user_via_auth(): void
    {
        // Arrange
        $user = $this->makeUser();
        $passkey = new Passkey();
        $passkey->setRelation('passkeeable', $user);
        $request = Request::create('/api/passkeys/login', 'POST');

        // Act
        (new CreateWebSessionAction())($passkey, $request);

        // Assert
        $this->assertSame($user, Auth::user());
    }

    public function test_logs_in_using_configured_session_guard(): void
    {
        // Arrange
        $user = $this->makeUser();
        $passkey = new Passkey();
        $passkey->setRelation('passkeeable', $user);
        $request = Request::create('/api/passkeys/login', 'POST');

        config([
            'auth.defaults.guard' => 'undefined_guard',
            'passkey.session_guard' => 'web',
        ]);

        // Act
        (new CreateWebSessionAction())($passkey, $request);

        // Assert
        $this->assertSame($user, Auth::guard('web')->user());
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
        (new CreateWebSessionAction())($passkey, $request);
    }
}
