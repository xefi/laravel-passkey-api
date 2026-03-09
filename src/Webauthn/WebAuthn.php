<?php

namespace Xefi\LaravelPasskey\Webauthn;

use Xefi\LaravelPasskey\Models\Passkey;
use Xefi\LaravelPasskey\Exceptions\InvalidCoseKeyException;
use Xefi\LaravelPasskey\Exceptions\InvalidSignatureException;
use Xefi\LaravelPasskey\Exceptions\MalformedClientDataException;
use Xefi\LaravelPasskey\Exceptions\MalformedAttestationException;
use Xefi\LaravelPasskey\Exceptions\UnsupportedAlgorithmException;
use Xefi\LaravelPasskey\Exceptions\InvalidAttestationFormatException;

/**
 * WebAuthn service for handling passkey operations.
 * 
 * This service implements the Web Authentication API (WebAuthn) specification for creating
 * and using public-key-based credentials (passkeys) to authenticate users on web applications.
 * 
 * Standards and Specifications:
 * 
 * - W3C Web Authentication (WebAuthn) Level 2
 *   https://www.w3.org/TR/webauthn-2/
 *   Main specification defining the JavaScript API for creating and using public-key credentials
 * 
 * - FIDO2 Project
 *   https://fidoalliance.org/fido2/
 *   Collaborative project between FIDO Alliance and W3C encompassing WebAuthn and CTAP
 * 
 * - Client to Authenticator Protocol (CTAP)
 *   https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html
 *   Defines communication between client (browser/OS) and authenticator (security key, biometrics)
 * 
 * - RFC 8809 - Registries for Web Authentication (WebAuthn)
 *   https://www.rfc-editor.org/rfc/rfc8809.html
 *   IANA registries for attestation statement format identifiers and extension identifiers
 * 
 * - COSE (CBOR Object Signing and Encryption)
 *   RFC 8152: https://www.rfc-editor.org/rfc/rfc8152.html
 *   Defines algorithm identifiers and key formats used in WebAuthn
 * 
 * Note: "Passkey" is a marketing term for a WebAuthn credential conforming to FIDO2 standards,
 * not an independent specification.
 * 
 * @package Xefi\LaravelPasskey\Webauthn
 */
final class WebAuthn
{
    /**
     * Generate registration options for creating a new passkey.
     * 
     * Creates the PublicKeyCredentialCreationOptions object required by the
     * navigator.credentials.create() JavaScript API.
     * 
     * References:
     * - WebAuthn Level 2 § 5.4: Options for Credential Creation
     *   https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialcreationoptions
     * - WebAuthn Level 2 § 6.4.1: Register a New Credential
     *   https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential
     * - COSE Algorithm Identifiers (RFC 8152 § 8.1)
     *   https://www.rfc-editor.org/rfc/rfc8152.html#section-8.1
     * 
     * @param string $app_name Relying Party name (displayed to user)
     * @param string $app_url Relying Party URL (used to extract RP ID)
     * @param string $user_id User identifier (converted to binary)
     * @param string $email User email (used as username)
     * @param string $display_name User display name
     * @return array PublicKeyCredentialCreationOptions structure
     */
    public function generate_register_options(
        string $app_name,
        string $app_url,
        string $user_id,
        string $email,
        string $display_name
    ): array {
        $challenge = $this->generate_challenge();

        return [
            'challenge' => $challenge,
            'rp' => [
                'name' => $app_name,
                'id' => parse_url($app_url, PHP_URL_HOST),
            ],
            'user' => [
                'id' => base64_encode(pack('N', intval($user_id))),
                'name' => $email,
                'displayName' => $display_name,
            ],
            'pubKeyCredParams' => [
                ['type' => 'public-key', 'alg' => Algorithm::ES256->value],
                ['type' => 'public-key', 'alg' => Algorithm::RS256->value],
            ],
            'timeout' => config('passkey.timeout', 600000),
            'attestation' => 'none',
            'authenticatorSelection' => [
                'residentKey' => 'preferred',
                'userVerification' => 'preferred',
            ],
        ];
    }

    /**
     * Generate authentication options for verifying an existing passkey.
     * 
     * Creates the PublicKeyCredentialRequestOptions object required by the
     * navigator.credentials.get() JavaScript API.
     * 
     * References:
     * - WebAuthn Level 2 § 5.5: Options for Assertion Generation
     *   https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialrequestoptions
     * - WebAuthn Level 2 § 6.4.3: Verifying an Authentication Assertion
     *   https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion
     * 
     * @param string $challenge Base64url-encoded challenge
     * @param string $credential_id Base64-encoded credential identifier
     * @return array PublicKeyCredentialRequestOptions structure
     */
    public function generate_verify_options(string $challenge, string $credential_id): array
    {
        return [
            'challenge' => $challenge,
            'allowCredentials' => [
                [
                    'id' => $credential_id,
                    'type' => 'public-key'
                ]
            ],
            'timeout' => config('passkey.timeout', 600000),
            'userVerification' => 'required'
        ];
    }

    /**
     * Extract credential data from registration response.
     * 
     * Parses the attestation object and extracts the credential ID and public key
     * from the authenticator data. Uses CBOR decoding as specified in WebAuthn.
     * 
     * References:
     * - WebAuthn Level 2 § 6.5.1: Attestation Object
     *   https://www.w3.org/TR/webauthn-2/#sctn-attestation
     * - WebAuthn Level 2 § 6.5.4: Authenticator Data
     *   https://www.w3.org/TR/webauthn-2/#sctn-authenticator-data
     * - CBOR (RFC 8949): Concise Binary Object Representation
     *   https://www.rfc-editor.org/rfc/rfc8949.html
     * - COSE Key Format (RFC 8152 § 7)
     *   https://www.rfc-editor.org/rfc/rfc8152.html#section-7
     * 
     * @param string $client_data_json Base64url-encoded client data JSON
     * @param string $attestation_object Base64url-encoded attestation object
     * @return array Contains 'credential_id' and 'public_key' (both base64-encoded)
     * @throws InvalidAttestationFormatException If attestation object is not a valid CBOR map
     * @throws MalformedAttestationException If attestation object is missing required fields
     */
    public function get_data_for_register(string $client_data_json, string $attestation_object): array
    {
        $client_data = json_decode(base64_decode($client_data_json), true);

        $this->validate_client_data($client_data, 'webauthn.create');

        $attestation_raw = $this->decode_base64_url($attestation_object);

        // Use CBOR library to decode attestation object
        $stream = new \CBOR\StringStream($attestation_raw);
        $attestation_map = (new \CBOR\Decoder())->decode($stream);

        // Convert CBOR map to array
        if ($attestation_map instanceof \CBOR\MapObject) {
            $attestation_array = [];
            foreach ($attestation_map as $key => $value) {
                $attestation_array[$key] = $value;
            }
        } else {
            throw new InvalidAttestationFormatException();
        }

        if (!isset($attestation_array['authData'])) {
            throw new MalformedAttestationException();
        }

        $auth_data = $attestation_array['authData'];
        if ($auth_data instanceof \CBOR\ByteStringObject) {
            $auth_data = $auth_data->getValue();
        }

        $parsed = $this->parse_auth_data($auth_data);

        $result = [
            'credential_id' => base64_encode($parsed['credential_id']),
            'public_key' => base64_encode($parsed['public_key_cbor']),
        ];

        return $result;
    }

    /**
     * Verify an authentication assertion signature.
     * 
     * Validates the digital signature created by the authenticator during authentication.
     * Supports ES256 (ECDSA P-256) and RS256 (RSA-PSS) algorithms as defined in COSE.
     * 
     * References:
     * - WebAuthn Level 2 § 7.2: Verifying an Authentication Assertion
     *   https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion
     * - COSE Algorithm -7 (ES256): ECDSA w/ SHA-256
     *   RFC 8152 § 8.1: https://www.rfc-editor.org/rfc/rfc8152.html#section-8.1
     * - COSE Algorithm -257 (RS256): RSASSA-PKCS1-v1_5 w/ SHA-256
     *   RFC 8152 § 8.1: https://www.rfc-editor.org/rfc/rfc8152.html#section-8.1
     * - SEC1: Elliptic Curve Cryptography (for EC key encoding)
     *   https://www.secg.org/sec1-v2.pdf
     * 
     * @param string $client_data_json Base64url-encoded client data JSON
     * @param string $authenticator_data Base64url-encoded authenticator data
     * @param string $signature Base64url-encoded signature
     * @param string $public_key Base64-encoded COSE public key
     * @return void
     * @throws InvalidSignatureException If signature verification fails
     * @throws InvalidCoseKeyException If the COSE key cannot be parsed
     * @throws UnsupportedAlgorithmException If the algorithm identifier is not supported
     * @see Algorithm For per-algorithm exceptions (MissingEcCoordinatesException, MissingRsaParametersException)
     */
    public function verify(
        string $client_data_json,
        string $authenticator_data,
        string $signature,
        string $public_key
    ): void {
        $client_data = json_decode(base64_decode($client_data_json), true);

        $this->validate_client_data($client_data, 'webauthn.get');

        $auth_data = $this->decode_base64_url($authenticator_data);

        $signature = $this->decode_base64_url($signature);

        $client_data_hash = hash('sha256', base64_decode($client_data_json), true);

        $signed_data = $auth_data . $client_data_hash;

        // Use COSE library to parse the public key
        $cose = base64_decode($public_key);

        // First decode CBOR to get the array representation
        $stream = new \CBOR\StringStream($cose);
        $coseData = (new \CBOR\Decoder())->decode($stream);

        // Helper function to convert CBOR objects to primitive values
        $convertCborValue = function ($value) use (&$convertCborValue) {
            if ($value instanceof \CBOR\ByteStringObject) {
                return $value->getValue();
            } elseif ($value instanceof \CBOR\NegativeIntegerObject) {
                return $value->getValue();
            } elseif ($value instanceof \CBOR\UnsignedIntegerObject) {
                return $value->getValue();
            } elseif ($value instanceof \CBOR\TextStringObject) {
                return $value->getValue();
            } elseif ($value instanceof \CBOR\MapObject) {
                $result = [];
                foreach ($value as $k => $v) {
                    $result[$convertCborValue($k)] = $convertCborValue($v);
                }
                return $result;
            } elseif ($value instanceof \CBOR\ListObject) {
                $result = [];
                foreach ($value as $v) {
                    $result[] = $convertCborValue($v);
                }
                return $result;
            } else {
                // For primitives (int, string, etc.) or unknown types, return as-is
                return $value;
            }
        };

        // Convert CBOR object to array for Cose\Key\Key
        if ($coseData instanceof \CBOR\MapObject) {
            $coseArray = [];

            // MapObject iteration returns MapItem objects, not key-value pairs
            foreach ($coseData as $mapItem) {
                if ($mapItem instanceof \CBOR\MapItem) {
                    $key = $convertCborValue($mapItem->getKey());
                    $value = $convertCborValue($mapItem->getValue());
                } else {
                    continue;
                }

                $coseArray[$key] = $value;
            }
        } else {
            throw new InvalidCoseKeyException();
        }

        $coseKey = \Cose\Key\Key::create($coseArray);

        // Convert COSE key to PEM format for OpenSSL verification
        $algorithm = Algorithm::tryFrom($coseKey->alg())
            ?? throw new UnsupportedAlgorithmException("Unsupported algorithm: {$coseKey->alg()}");

        ['pem' => $pem, 'opensslAlgo' => $opensslAlgo] = $algorithm->buildPem($coseKey);

        $signature_verify = openssl_verify($signed_data, $signature, $pem, $opensslAlgo);

        if ($signature_verify !== 1) {
            throw new InvalidSignatureException();
        }
    }

    /**
     * Generate a cryptographically secure random challenge.
     * 
     * Creates a base64url-encoded random challenge for use in credential creation
     * and authentication ceremonies.
     * 
     * References:
     * - WebAuthn Level 2 § 13.4.3: Cryptographic Challenges
     *   https://www.w3.org/TR/webauthn-2/#sctn-cryptographic-challenges
     * - RFC 4648 § 5: Base64url Encoding
     *   https://www.rfc-editor.org/rfc/rfc4648.html#section-5
     * 
     * @return string Base64url-encoded challenge (no padding)
     */
    public function generate_challenge(): string
    {
        $length = config('passkey.challenge_length', 32);
        return rtrim(strtr(base64_encode(random_bytes($length)), '+/', '-_'), '=');
    }

    /**
     * Decode a base64url-encoded string.
     * 
     * Converts base64url encoding (URL-safe, no padding) to standard base64
     * and decodes it to binary data.
     * 
     * References:
     * - RFC 4648 § 5: Base 64 Encoding with URL and Filename Safe Alphabet
     *   https://www.rfc-editor.org/rfc/rfc4648.html#section-5
     * 
     * @param string $input Base64url-encoded string
     * @return string Decoded binary data
     */
    public function decode_base64_url(string $input): string
    {
        $input .= str_repeat('=', (4 - strlen($input) % 4) % 4);
        return base64_decode(strtr($input, '-_', '+/'), true);
    }

    /**
     * Validate the client data JSON structure and type.
     * 
     * Ensures the client data contains required fields and matches the expected
     * ceremony type (webauthn.create or webauthn.get).
     * 
     * References:
     * - WebAuthn Level 2 § 6.5.2: Client Data
     *   https://www.w3.org/TR/webauthn-2/#client-data
     * - WebAuthn Level 2 § 5.8.1: Client Data Used in WebAuthn Signatures
     *   https://www.w3.org/TR/webauthn-2/#dictdef-collectedclientdata
     * 
     * @param array $client_data Decoded client data JSON
     * @param string $expected_type Expected type ('webauthn.create' or 'webauthn.get')
     * @return void
     * @throws MalformedClientDataException If client data is malformed or type doesn't match
     */
    public function validate_client_data(array $client_data, string $expected_type): void
    {
        if (!isset($client_data['type'], $client_data['challenge'], $client_data['origin'])) {
            throw new MalformedClientDataException();
        }

        if ($client_data['type'] !== $expected_type) {
            throw new MalformedClientDataException("Unexpected clientData type: {$client_data['type']}");
        }
    }

    /**
     * Parse authenticator data structure.
     * 
     * Extracts components from the binary authenticator data including RP ID hash,
     * flags, signature counter, AAGUID, credential ID, and public key.
     * 
     * References:
     * - WebAuthn Level 2 § 6.5.4: Authenticator Data
     *   https://www.w3.org/TR/webauthn-2/#sctn-authenticator-data
     * - WebAuthn Level 2 § 6.5.4.1: Flags
     *   https://www.w3.org/TR/webauthn-2/#flags
     * - WebAuthn Level 2 § 6.5.4.4: Attested Credential Data
     *   https://www.w3.org/TR/webauthn-2/#sctn-attested-credential-data
     * 
     * @param string $auth_data Binary authenticator data
     * @return array Parsed components: rp_id_hash, flags, sign_count, aaguid, credential_id, public_key_cbor
     */
    public function parse_auth_data(string $auth_data): array
    {
        $offset = 0;
        $rp_id_hash = substr($auth_data, $offset, 32);
        $offset += 32;
        $flags = ord($auth_data[$offset]);
        $offset += 1;
        $sign_count = unpack("N", substr($auth_data, $offset, 4))[1];
        $offset += 4;
        $aaguid = substr($auth_data, $offset, 16);
        $offset += 16;
        $cred_id_length = unpack("n", substr($auth_data, $offset, 2))[1];
        $offset += 2;
        $credential_id = substr($auth_data, $offset, $cred_id_length);
        $offset += $cred_id_length;
        $public_key_cbor = substr($auth_data, $offset);

        return compact('rp_id_hash', 'flags', 'sign_count', 'aaguid', 'credential_id', 'public_key_cbor');
    }

    /**
     * Extract the challenge from client data JSON.
     * 
     * Decodes the client data JSON and extracts the challenge value,
     * converting it back to base64url format.
     * 
     * References:
     * - WebAuthn Level 2 § 5.8.1: CollectedClientData
     *   https://www.w3.org/TR/webauthn-2/#dictdef-collectedclientdata
     * 
     * @param string $client_data_json Base64url-encoded client data JSON
     * @return string Base64url-encoded challenge
     */
    public function get_challenge_from_client_data_json(string $client_data_json): string
    {
        $client_data = json_decode(base64_decode($client_data_json), true);
        $challenge = base64_decode(strtr($client_data['challenge'], '-_', '+/'));

        return rtrim(strtr(base64_encode($challenge), '+/', '-_'), '=');
    }

    /**
     * Register a new passkey for a user.
     * 
     * Processes the registration response from the authenticator, validates the data,
     * and persists the passkey to the database.
     * 
     * References:
     * - WebAuthn Level 2 § 7.1: Registering a New Credential
     *   https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential
     * 
     * @param array $validated Validated registration response data
     * @param mixed $userId User identifier
     * @return Passkey Created passkey model instance
     */
    public function registerPasskey(array $validated, $userId): Passkey
    {
        // Extract challenge from clientDataJSON
        $challenge = $this->get_challenge_from_client_data_json(
            $validated['response']['clientDataJSON']
        );

        // Parse credential data
        $parsed = $this->get_data_for_register(
            $validated['response']['clientDataJSON'],
            $validated['response']['attestationObject']
        );

        // Create and persist the passkey
        $passkey = Passkey::create([
            'user_id' => $userId,
            'label' => $validated['label'] ?? 'Default Passkey',
            'credential_id' => $parsed['credential_id'],
            'challenge' => $challenge,
            'public_key' => $parsed['public_key'],
        ]);

        return $passkey;
    }

    /**
     * Verify a passkey authentication assertion.
     * 
     * Looks up the passkey by credential ID, verifies the signature,
     * and returns the authenticated passkey.
     * 
     * References:
     * - WebAuthn Level 2 § 7.2: Verifying an Authentication Assertion
     *   https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion
     * 
     * @param string $credentialIdBase64Url Base64url-encoded credential ID
     * @param array $response Authentication response data
     * @return Passkey Verified passkey model instance
     * @throws \Exception If passkey not found or signature verification fails
     */
    public function verifyPasskey(string $credentialIdBase64Url, array $response): Passkey
    {
        // Convert base64url to base64 standard for database lookup
        // The client sends base64url (- and _ chars, no padding)
        // But we store base64 standard (+ and / chars, with padding)
        $credentialIdBase64 = str_pad(
            strtr($credentialIdBase64Url, '-_', '+/'),
            strlen($credentialIdBase64Url) + (4 - strlen($credentialIdBase64Url) % 4) % 4,
            '=',
            STR_PAD_RIGHT
        );

        // Find the passkey by credential_id (base64 standard format)
        $passkey = Passkey::where('credential_id', $credentialIdBase64)->first();

        if (!$passkey) {
            throw new \Exception('Passkey not found');
        }

        // Verify the signature using Webauthn
        $this->verify(
            $response['clientDataJSON'],
            $response['authenticatorData'],
            $response['signature'],
            $passkey->public_key
        );

        return $passkey;
    }
}
