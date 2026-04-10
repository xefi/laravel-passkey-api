<?php

namespace Xefi\LaravelPasskey\Tests\Unit\Traits;

use Xefi\LaravelPasskey\Tests\TestCase;
use Xefi\LaravelPasskey\Traits\HasPasskeys;

class HasPasskeysTest extends TestCase
{
    private function makeModel(array $attributes = [], mixed $key = 1): object
    {
        return new class($attributes, $key) {
            use HasPasskeys;

            public ?string $name;
            public ?string $email;
            private mixed $key;

            public function __construct(array $attributes, mixed $key)
            {
                $this->name = $attributes['name'] ?? null;
                $this->email = $attributes['email'] ?? null;
                $this->key = $key;
            }

            public function getKey(): mixed { return $this->key; }

            // Stub trait methods that require Eloquent
            public function passkeys(): void {}
            protected static function bootHasPasskeys(): void {}
        };
    }

    public function test_get_passkey_display_name_returns_name_when_present(): void
    {
        // Arrange
        $model = $this->makeModel(['name' => 'Alice', 'email' => 'alice@example.com']);

        // Act & Assert
        $this->assertEquals('Alice', $model->getPasskeyDisplayName());
    }

    public function test_get_passkey_display_name_falls_back_to_email_when_name_is_null(): void
    {
        // Arrange
        $model = $this->makeModel(['name' => null, 'email' => 'alice@example.com']);

        // Act & Assert
        $this->assertEquals('alice@example.com', $model->getPasskeyDisplayName());
    }

    public function test_get_passkey_display_name_falls_back_to_key_when_name_and_email_are_null(): void
    {
        // Arrange
        $model = $this->makeModel(['name' => null, 'email' => null], key: 42);

        // Act & Assert
        $this->assertEquals('42', $model->getPasskeyDisplayName());
    }

    public function test_get_passkey_email_returns_email_when_present(): void
    {
        // Arrange
        $model = $this->makeModel(['email' => 'bob@example.com']);

        // Act & Assert
        $this->assertEquals('bob@example.com', $model->getPasskeyEmail());
    }

    public function test_get_passkey_email_returns_empty_string_when_email_is_null(): void
    {
        // Arrange
        $model = $this->makeModel(['email' => null]);

        // Act & Assert
        $this->assertEquals('', $model->getPasskeyEmail());
    }

    public function test_display_name_can_be_overridden_in_subclass(): void
    {
        // Arrange
        $model = new class extends \stdClass {
            use HasPasskeys;

            public string $username = 'alice99';

            public function getPasskeyDisplayName(): string { return $this->username; }
            public function getPasskeyEmail(): string { return ''; }
            public function getKey(): mixed { return 1; }
            public function passkeys(): void {}
            protected static function bootHasPasskeys(): void {}
        };

        // Act & Assert
        $this->assertEquals('alice99', $model->getPasskeyDisplayName());
    }
}
