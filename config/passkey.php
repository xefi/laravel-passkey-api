<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Passkey Configuration
    |--------------------------------------------------------------------------
    |
    | Configuration options for the passkey authentication package.
    |
    */

    'enabled' => env('PASSKEY_ENABLED', true),

    'timeout' => env('PASSKEY_TIMEOUT', 60000),

    'challenge_length' => env('PASSKEY_CHALLENGE_LENGTH', 32),

    /*
    |--------------------------------------------------------------------------
    | User Model
    |--------------------------------------------------------------------------
    |
    | The User model class to use for passkey relationships.
    | Override this if you use a custom User model.
    |
    */

    'user_model' => env('PASSKEY_USER_MODEL', 'App\Models\User'),

    /*
    |--------------------------------------------------------------------------
    | Middleware Configuration
    |--------------------------------------------------------------------------
    |
    | Define the middleware groups for the passkey routes.
    |
    */

    'middleware' => [
        'default' => ['api'],
        'auth' => ['auth:sanctum'],
    ],
];
