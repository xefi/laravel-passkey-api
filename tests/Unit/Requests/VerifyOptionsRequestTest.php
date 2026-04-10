<?php

namespace Xefi\LaravelPasskey\Tests\Unit\Requests;

use Illuminate\Support\Facades\Validator;
use Xefi\LaravelPasskey\Http\Requests\VerifyOptionsRequest;
use Xefi\LaravelPasskey\Tests\TestCase;

class VerifyOptionsRequestTest extends TestCase
{
    private function rules(): array
    {
        return (new VerifyOptionsRequest())->rules();
    }

    public function test_credential_id_is_required(): void
    {
        // Arrange & Act
        $validator = Validator::make([], $this->rules());

        // Assert
        $this->assertTrue($validator->fails());
        $this->assertArrayHasKey('credential_id', $validator->errors()->toArray());
    }

    public function test_passes_with_valid_credential_id(): void
    {
        // Arrange & Act
        $validator = Validator::make(
            ['credential_id' => 'base64url-encoded-credential-id'],
            $this->rules()
        );

        // Assert
        $this->assertFalse($validator->fails());
    }
}
