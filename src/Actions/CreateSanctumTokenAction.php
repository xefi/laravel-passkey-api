<?php

namespace Xefi\LaravelPasskey\Actions;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Xefi\LaravelPasskey\Contracts\PasskeyAuthAction;
use Xefi\LaravelPasskey\Exceptions\UserNotFoundException;
use Xefi\LaravelPasskey\Models\Passkey;

class CreateSanctumTokenAction implements PasskeyAuthAction
{
    public function __invoke(Passkey $passkey, Request $request): JsonResponse
    {
        $user = $passkey->passkeeable;

        if (!$user) {
            throw new UserNotFoundException();
        }

        $token = $user->createToken('passkey-auth')->plainTextToken;

        return response()->json([
            'user' => [
                'id' => $user->id,
                'name' => $user->getPasskeyDisplayName(),
                'email' => $user->getPasskeyEmail(),
            ],
            'token' => $token,
        ]);
    }
}
