<?php

namespace Xefi\LaravelPasskey\Actions;

use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;

use Xefi\LaravelPasskey\Models\Passkey;
use Xefi\LaravelPasskey\Contracts\PasskeyAuthAction;
use Xefi\LaravelPasskey\Exceptions\UserNotFoundException;

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
                'id' => $user->getKey(),
                'name' => $user->getPasskeyDisplayName(),
                'email' => $user->getPasskeyEmail(),
            ],
            'token' => $token,
        ]);
    }
}
