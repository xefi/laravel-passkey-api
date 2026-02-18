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

Route::prefix('api/passkeys')->group(function () {
    Route::post('/verify/options', [\Xefi\LaravelPasskey\Http\Controllers\PasskeyController::class, 'verifyOptions']);
    Route::post('/verify', [\Xefi\LaravelPasskey\Http\Controllers\PasskeyController::class, 'verify']);
    Route::post('/login', [\Xefi\LaravelPasskey\Http\Controllers\PasskeyController::class, 'auth']);
});

Route::prefix('api/passkeys')->middleware('auth')->group(function () {
    Route::get('/', [\Xefi\LaravelPasskey\Http\Controllers\PasskeyController::class, 'index']);
    Route::post('/register/options', [\Xefi\LaravelPasskey\Http\Controllers\PasskeyController::class, 'registerOptions']);
    Route::post('/register', [\Xefi\LaravelPasskey\Http\Controllers\PasskeyController::class, 'register']);
});
