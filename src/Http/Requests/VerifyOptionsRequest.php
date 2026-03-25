<?php

namespace Xefi\LaravelPasskey\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class VerifyOptionsRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return [
            'credential_id' => ['required', 'string'],
        ];
    }
}
