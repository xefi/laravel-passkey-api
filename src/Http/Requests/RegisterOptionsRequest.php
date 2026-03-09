<?php

namespace Xefi\LaravelPasskey\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class RegisterOptionsRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        return true;
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array<string, \Illuminate\Contracts\Validation\ValidationRule|array<mixed>|string>
     */
    public function rules(): array
    {
        return [
            'app_name' => ['required', 'string', 'max:255'],
            'app_url' => ['required', 'url', 'max:255'],
        ];
    }
}
