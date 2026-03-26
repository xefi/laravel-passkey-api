<?php

namespace Xefi\LaravelPasskey\Contracts;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Xefi\LaravelPasskey\Models\Passkey;

interface PasskeyAuthAction
{
    public function __invoke(Passkey $passkey, Request $request): JsonResponse;
}
