<?php

namespace Xefi\LaravelPasskey\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Routing\Controller;
use Illuminate\Auth\AuthenticationException;

use Xefi\LaravelPasskey\Models\Passkey;
use Xefi\LaravelPasskey\Webauthn\WebAuthn;
use Xefi\LaravelPasskey\Http\Requests\IndexRequest;
use Xefi\LaravelPasskey\Http\Requests\VerifyRequest;
use Xefi\LaravelPasskey\Http\Requests\RegisterRequest;
use Xefi\LaravelPasskey\Exceptions\UserNotFoundException;
use Xefi\LaravelPasskey\Http\Requests\VerifyOptionsRequest;
use Xefi\LaravelPasskey\Exceptions\PasskeyNotFoundException;
use Xefi\LaravelPasskey\Http\Requests\RegisterOptionsRequest;

class PasskeyController extends Controller
{
    private WebAuthn $passkey;

    public function __construct(WebAuthn $passkey)
    {
        $this->passkey = $passkey;
    }

    /**
     * Get a list of passkeys for the authenticated user.
     *
     * @param IndexRequest $request
     * @return JsonResponse
     */
    public function index(IndexRequest $request): JsonResponse
    {
        $user = $request->user();

        $passkeys = Passkey::query()->where('user_id', $user->id)
            ->get(['id', 'user_id', 'label', 'credential_id', 'created_at']);

        return response()->json($passkeys);
    }

    /**
     * Get registration options for creating a new passkey.
     *
     * @param RegisterOptionsRequest $request
     * @return JsonResponse
     */
    public function registerOptions(RegisterOptionsRequest $request): JsonResponse
    {
        $user = $request->user();

        if (!$user) {
            throw new AuthenticationException('Unauthenticated');
        }

        $validated = $request->validated();

        $options = $this->passkey->generate_register_options(
            $validated['app_name'],
            $validated['app_url'],
            (string) $user->id,
            $user->email,
            $user->name
        );

        return response()->json($options);
    }

    /**
     * Register a new passkey.
     *
     * @param RegisterRequest $request
     * @return JsonResponse
     */
    public function register(RegisterRequest $request): JsonResponse
    {
        $validated = $request->validated();

        $passkey = $this->passkey->registerPasskey(
            $validated,
            $request->user()->id
        );

        return response()->json([
            'passkey' => [
                'id' => $passkey->id,
                'label' => $passkey->label,
                'credential_id' => $passkey->credential_id,
                'created_at' => $passkey->created_at,
            ],
        ]);
    }

    /**
     * Get verification options for authenticating with a passkey.
     *
     * @param VerifyOptionsRequest $request
     * @return JsonResponse
     */
    public function verifyOptions(VerifyOptionsRequest $request): JsonResponse
    {
        $validated = $request->validated();

        $passkey = Passkey::query()->where('credential_id', $validated['credential_id'])->first();

        if (is_null($passkey)) {
            throw new PasskeyNotFoundException();
        }

        return response()->json([
            'challenge' => $passkey->challenge,
            'allowCredentials' => [
                [
                    'id' => $passkey->credential_id,
                    'type' => 'public-key',
                ]
            ],
            'timeout' => config('passkey.timeout'),
            'userVerification' => 'preferred',
        ]);
    }

    /**
     * Verify a passkey authentication attempt.
     *
     * @param VerifyRequest $request
     * @return JsonResponse
     */
    public function verify(VerifyRequest $request): JsonResponse
    {
        $validated = $request->validated();

        $passkey = $this->passkey->verifyPasskey(
            $validated['id'],
            $validated['response']
        );

        return response()->json([
            'user' => ['id' => $passkey->user_id],
            'passkey' => ['id' => $passkey->id],
        ]);
    }

    /**
     * Authenticate a user with a passkey and create a session.
     *
     * @param VerifyRequest $request
     * @return JsonResponse
     */
    public function auth(VerifyRequest $request): JsonResponse
    {
        $validated = $request->validated();

        $passkey = $this->passkey->verifyPasskey(
            $validated['id'],
            $validated['response']
        );

        $user = $passkey->user;

        if (!$user) {
            throw new UserNotFoundException();
        }

        $token = $user->createToken('passkey-auth')->plainTextToken;

        return response()->json([
            'user' => [
                'id' => $user->id,
                'name' => $user->name ?? null,
                'email' => $user->email ?? null,
            ],
            'token' => $token,
        ]);
    }
}
