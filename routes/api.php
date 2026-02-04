<?php

use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| Passkey API Routes
|--------------------------------------------------------------------------
|
| Here are the API routes for the passkey package.
|
*/

// Public passkey routes (for authentication)
Route::prefix('api/passkeys')->group(function () {
    Route::post('/verify_options', [\Xefi\LaravelPasskey\Http\Controllers\PasskeyController::class, 'verifyOptions']);
    Route::post('/verify', [\Xefi\LaravelPasskey\Http\Controllers\PasskeyController::class, 'verify']);
    Route::post('/auth', [\Xefi\LaravelPasskey\Http\Controllers\PasskeyController::class, 'auth']);
});

// Protected passkey routes (require authentication)
Route::prefix('api/passkeys')->middleware('auth')->group(function () {
    Route::get('/', [\Xefi\LaravelPasskey\Http\Controllers\PasskeyController::class, 'index']);
    Route::post('/register_options', [\Xefi\LaravelPasskey\Http\Controllers\PasskeyController::class, 'registerOptions']);
    Route::post('/register', [\Xefi\LaravelPasskey\Http\Controllers\PasskeyController::class, 'register']);
});
