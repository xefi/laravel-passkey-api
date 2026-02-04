<?php

namespace Thomyris\LaravelPasskey\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class RegisterRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return [
            'label' => 'nullable|string|max:255',
            'id' => 'required|string',
            'rawId' => 'required|string',
            'response' => 'required|array',
            'response.clientDataJSON' => 'required|string',
            'response.attestationObject' => 'required|string',
            'type' => 'required|string|in:public-key',
        ];
    }

    public function messages(): array
    {
        return [
            'label.string' => 'The label must be a string.',
            'label.max' => 'The label may not be greater than 255 characters.',
            'id.required' => 'The credential ID is required.',
            'rawId.required' => 'The raw credential ID is required.',
            'response.required' => 'The response object is required.',
            'response.clientDataJSON.required' => 'The client data JSON is required.',
            'response.attestationObject.required' => 'The attestation object is required.',
            'type.required' => 'The credential type is required.',
            'type.in' => 'The credential type must be "public-key".',
        ];
    }
}
