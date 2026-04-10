<?php

namespace Xefi\LaravelPasskey\Tests\Unit\Requests;

use Illuminate\Support\Facades\Validator;
use Xefi\LaravelPasskey\Http\Requests\VerifyRequest;
use Xefi\LaravelPasskey\Tests\TestCase;

class VerifyRequestTest extends TestCase
{
    private function rules(): array
    {
        return (new VerifyRequest())->rules();
    }

    private function messages(): array
    {
        return (new VerifyRequest())->messages();
    }

    private function validData(): array
    {
        return [
            'id'    => 'credential-id',
            'rawId' => 'credential-id',
            'type'  => 'public-key',
            'response' => [
                'clientDataJSON'    => 'base64encodeddata',
                'authenticatorData' => 'base64encodeddata',
                'signature'         => 'base64encodedsig',
            ],
        ];
    }

    public function test_id_is_required(): void
    {
        $data = $this->validData();
        unset($data['id']);

        $validator = Validator::make($data, $this->rules(), $this->messages());

        $this->assertTrue($validator->fails());
        $this->assertArrayHasKey('id', $validator->errors()->toArray());
    }

    public function test_type_must_be_public_key(): void
    {
        $data         = $this->validData();
        $data['type'] = 'wrong-type';

        $validator = Validator::make($data, $this->rules(), $this->messages());

        $this->assertTrue($validator->fails());
        $this->assertArrayHasKey('type', $validator->errors()->toArray());
    }

    public function test_response_authenticator_data_is_required(): void
    {
        $data = $this->validData();
        unset($data['response']['authenticatorData']);

        $validator = Validator::make($data, $this->rules(), $this->messages());

        $this->assertTrue($validator->fails());
        $this->assertArrayHasKey('response.authenticatorData', $validator->errors()->toArray());
    }

    public function test_response_signature_is_required(): void
    {
        $data = $this->validData();
        unset($data['response']['signature']);

        $validator = Validator::make($data, $this->rules(), $this->messages());

        $this->assertTrue($validator->fails());
        $this->assertArrayHasKey('response.signature', $validator->errors()->toArray());
    }

    public function test_response_user_handle_is_optional(): void
    {
        $validator = Validator::make($this->validData(), $this->rules());

        $this->assertFalse($validator->fails());
    }

    public function test_custom_messages_are_defined_for_all_required_fields(): void
    {
        // Arrange & Act
        $messages = $this->messages();

        // Assert
        $this->assertArrayHasKey('id.required', $messages);
        $this->assertArrayHasKey('rawId.required', $messages);
        $this->assertArrayHasKey('type.required', $messages);
        $this->assertArrayHasKey('type.in', $messages);
        $this->assertArrayHasKey('response.required', $messages);
        $this->assertArrayHasKey('response.clientDataJSON.required', $messages);
        $this->assertArrayHasKey('response.authenticatorData.required', $messages);
        $this->assertArrayHasKey('response.signature.required', $messages);
    }

    public function test_custom_message_is_used_for_invalid_type(): void
    {
        $data         = $this->validData();
        $data['type'] = 'wrong-type';

        $validator = Validator::make($data, $this->rules(), $this->messages());

        $this->assertTrue($validator->fails());
        $this->assertStringContainsString(
            'public-key',
            $validator->errors()->first('type')
        );
    }

    public function test_passes_with_valid_data(): void
    {
        $validator = Validator::make($this->validData(), $this->rules());

        $this->assertFalse($validator->fails());
    }
}
