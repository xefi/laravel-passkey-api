<?php

namespace Xefi\LaravelPasskey\Tests\Unit\Requests;

use Illuminate\Support\Facades\Validator;
use Xefi\LaravelPasskey\Http\Requests\RegisterOptionsRequest;
use Xefi\LaravelPasskey\Tests\TestCase;

class RegisterOptionsRequestTest extends TestCase
{
    private function rules(): array
    {
        return (new RegisterOptionsRequest())->rules();
    }

    public function test_app_name_is_required(): void
    {
        // Arrange & Act
        $validator = Validator::make(['app_url' => 'https://example.com'], $this->rules());

        // Assert
        $this->assertTrue($validator->fails());
        $this->assertArrayHasKey('app_name', $validator->errors()->toArray());
    }

    public function test_app_url_is_required(): void
    {
        // Arrange & Act
        $validator = Validator::make(['app_name' => 'My App'], $this->rules());

        // Assert
        $this->assertTrue($validator->fails());
        $this->assertArrayHasKey('app_url', $validator->errors()->toArray());
    }

    public function test_app_url_must_be_a_valid_url(): void
    {
        // Arrange & Act
        $validator = Validator::make([
            'app_name' => 'My App',
            'app_url'  => 'not-a-url',
        ], $this->rules());

        // Assert
        $this->assertTrue($validator->fails());
        $this->assertArrayHasKey('app_url', $validator->errors()->toArray());
    }

    public function test_passes_with_valid_data(): void
    {
        // Arrange & Act
        $validator = Validator::make([
            'app_name' => 'My App',
            'app_url'  => 'https://example.com',
        ], $this->rules());

        // Assert
        $this->assertFalse($validator->fails());
    }
}
