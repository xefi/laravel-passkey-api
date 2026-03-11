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
