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
    | Define the middleware applied to passkey routes.
    |
    | "default" applies to all routes (public and protected).
    | "auth"    applies only to routes that require an authenticated user
    |           (list passkeys, register a new passkey).
    |
    | By default the 'auth' middleware uses Laravel's default guard. Override
    | with a specific guard if needed.
    |
    */

    'middleware' => [
        'default' => ['api'],
        'auth' => ['auth'],
    ],

    /*
    |--------------------------------------------------------------------------
    | Auth Action
    |--------------------------------------------------------------------------
    |
    | The action class responsible for creating an authenticated session or
    | token after passkey verification on the POST /login endpoint.
    |
    | The class must implement: Xefi\LaravelPasskey\Contracts\PasskeyAuthAction
    |
    | Built-in actions:
    |
    |   CreateSanctumTokenAction  — Returns a Laravel Sanctum personal access
    |                               token. Requires laravel/sanctum.
    |
    |   CreatePassportTokenAction — Returns a Laravel Passport access token
    |                               with expiry. Requires laravel/passport.
    |
    |   CreateWebSessionAction    — Logs the user into the default web guard
    |                               and returns user data without a token.
    |                               Use with session-based authentication. (default)
    |
    | You can also provide your own class to support custom guards or any
    | other authentication mechanism.
    |
    */

    // 'auth_action' => \Xefi\LaravelPasskey\Actions\CreateSanctumTokenAction::class,
    // 'auth_action' => \Xefi\LaravelPasskey\Actions\CreatePassportTokenAction::class,
    'auth_action' => \Xefi\LaravelPasskey\Actions\CreateWebSessionAction::class,
];
