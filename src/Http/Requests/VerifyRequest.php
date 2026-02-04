<?php

namespace Thomyris\LaravelPasskey\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class VerifyRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return [
            'id' => 'required|string',
            'rawId' => 'required|string',
            'type' => 'required|string|in:public-key',
            'response' => 'required|array',
            'response.clientDataJSON' => 'required|string',
            'response.authenticatorData' => 'required|string',
            'response.signature' => 'required|string',
            'response.userHandle' => 'nullable|string',
        ];
    }

    public function messages(): array
    {
        return [
            'id.required' => 'The credential ID is required.',
            'rawId.required' => 'The raw credential ID is required.',
            'type.required' => 'The credential type is required.',
            'type.in' => 'The credential type must be "public-key".',
            'response.required' => 'The response object is required.',
            'response.clientDataJSON.required' => 'The client data JSON is required.',
            'response.authenticatorData.required' => 'The authenticator data is required.',
            'response.signature.required' => 'The signature is required.',
        ];
    }
}
