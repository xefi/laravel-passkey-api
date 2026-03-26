<?php

namespace Xefi\LaravelPasskey\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Routing\Controller;
use Illuminate\Auth\AuthenticationException;

use Xefi\LaravelPasskey\Support\Utils;
use Xefi\LaravelPasskey\Models\Passkey;
use Xefi\LaravelPasskey\Webauthn\WebAuthn;
use Xefi\LaravelPasskey\Http\Requests\IndexRequest;
use Xefi\LaravelPasskey\Http\Requests\VerifyRequest;
use Xefi\LaravelPasskey\Http\Requests\RegisterRequest;
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
     * Get a list of passkeys for the authenticated model.
     *
     * @param IndexRequest $request
     * @return JsonResponse
     */
    public function index(IndexRequest $request): JsonResponse
    {
        $user = $request->user();

        $passkeys = $user->passkeys()
            ->get(['id', 'label', 'credential_id', 'created_at']);

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
            $user->getPasskeyEmail(),
            $user->getPasskeyDisplayName()
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
            $request->user()
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

        $credentialIdBase64 = Utils::convert_base64url_to_base64($validated['credential_id']);

        $passkey = Passkey::query()->where('credential_id', $credentialIdBase64)->first();

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
            'passkeeable_id' => $passkey->passkeeable_id,
            'passkeeable_type' => $passkey->passkeeable_type,
            'passkey' => ['id' => $passkey->id],
        ]);
    }

    /**
     * Authenticate a model with a passkey.
     *
     * The response is determined by the configured PasskeyAuthAction, which
     * defaults to creating a Sanctum token. Swap it via config('passkey.auth_action')
     * to support sessions, Passport, or any other guard.
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

        return app(\Xefi\LaravelPasskey\Contracts\PasskeyAuthAction::class)($passkey, $request);
    }
}
