<?php

namespace Xefi\LaravelPasskey\Actions;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Xefi\LaravelPasskey\Contracts\PasskeyAuthAction;
use Xefi\LaravelPasskey\Exceptions\UserNotFoundException;
use Xefi\LaravelPasskey\Models\Passkey;

class CreateWebSessionAction implements PasskeyAuthAction
{
    public function __invoke(Passkey $passkey, Request $request): JsonResponse
    {
        $user = $passkey->passkeeable;

        if (!$user) {
            throw new UserNotFoundException();
        }

        Auth::login($user);

        return response()->json([
            'user' => [
                'id' => $user->id,
                'name' => $user->getPasskeyDisplayName(),
                'email' => $user->getPasskeyEmail(),
            ],
        ]);
    }
}
