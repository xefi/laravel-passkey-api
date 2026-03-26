<?php

namespace Xefi\LaravelPasskey\Tests\Unit\Requests;

use Illuminate\Support\Facades\Validator;
use Xefi\LaravelPasskey\Http\Requests\RegisterRequest;
use Xefi\LaravelPasskey\Tests\TestCase;

class RegisterRequestTest extends TestCase
{
    private function rules(): array
    {
        return (new RegisterRequest())->rules();
    }

    private function validData(): array
    {
        return [
            'id'    => 'credential-id',
            'rawId' => 'credential-id',
            'type'  => 'public-key',
            'response' => [
                'clientDataJSON'    => 'base64encodeddata',
                'attestationObject' => 'base64encodeddata',
            ],
        ];
    }

    public function test_id_is_required(): void
    {
        $data = $this->validData();
        unset($data['id']);

        $validator = Validator::make($data, $this->rules());

        $this->assertTrue($validator->fails());
        $this->assertArrayHasKey('id', $validator->errors()->toArray());
    }

    public function test_raw_id_is_required(): void
    {
        $data = $this->validData();
        unset($data['rawId']);

        $validator = Validator::make($data, $this->rules());

        $this->assertTrue($validator->fails());
        $this->assertArrayHasKey('rawId', $validator->errors()->toArray());
    }

    public function test_type_must_be_public_key(): void
    {
        $data         = $this->validData();
        $data['type'] = 'invalid-type';

        $validator = Validator::make($data, $this->rules());

        $this->assertTrue($validator->fails());
        $this->assertArrayHasKey('type', $validator->errors()->toArray());
    }

    public function test_response_client_data_json_is_required(): void
    {
        $data = $this->validData();
        unset($data['response']['clientDataJSON']);

        $validator = Validator::make($data, $this->rules());

        $this->assertTrue($validator->fails());
        $this->assertArrayHasKey('response.clientDataJSON', $validator->errors()->toArray());
    }

    public function test_response_attestation_object_is_required(): void
    {
        $data = $this->validData();
        unset($data['response']['attestationObject']);

        $validator = Validator::make($data, $this->rules());

        $this->assertTrue($validator->fails());
        $this->assertArrayHasKey('response.attestationObject', $validator->errors()->toArray());
    }

    public function test_label_is_optional(): void
    {
        // Arrange — no label provided
        $validator = Validator::make($this->validData(), $this->rules());

        // Assert
        $this->assertFalse($validator->fails());
    }

    public function test_passes_with_valid_data(): void
    {
        $data          = $this->validData();
        $data['label'] = 'My Passkey';

        $validator = Validator::make($data, $this->rules());

        $this->assertFalse($validator->fails());
    }
}
