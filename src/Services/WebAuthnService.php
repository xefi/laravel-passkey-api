<?php

namespace Thomyris\LaravelPasskey\Services;

use Thomyris\LaravelPasskey\Models\Passkey;

/**
 * WebAuthn service for handling passkey operations.
 */
final class WebAuthnService
{
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
                ['type' => 'public-key', 'alg' => -7],   // ES256
                ['type' => 'public-key', 'alg' => -257], // RS256
            ],
            'timeout' => config('passkey.timeout', 600000),
            'attestation' => 'none',
            'authenticatorSelection' => [
                'residentKey' => 'preferred',
                'userVerification' => 'preferred',
            ],
        ];
    }

    public function generate_verify_options(string $challenge, string $credential_id): array
    {
        return [
            'challenge' => $challenge,
            'allowCredentials' => [[
                'id' => $credential_id,
                'type' => 'public-key'
            ]],
            'timeout' => config('passkey.timeout', 600000),
            'userVerification' => 'required'
        ];
    }

    public function get_data_for_register(string $client_data_json, string $attestation_object): array
    {
        \Log::debug('get_data_for_register: Starting', [
            'client_data_json_length' => strlen($client_data_json),
            'attestation_object_length' => strlen($attestation_object),
        ]);

        $client_data = json_decode(base64_decode($client_data_json), true);
        \Log::debug('get_data_for_register: Decoded client data', [
            'client_data' => $client_data,
        ]);

        $this->validate_client_data($client_data, 'webauthn.create');
        \Log::debug('get_data_for_register: Client data validated');

        $attestation_raw = $this->decode_base64_url($attestation_object);
        \Log::debug('get_data_for_register: Decoded attestation object', [
            'attestation_raw_length' => strlen($attestation_raw),
        ]);

        // Use CBOR library to decode attestation object
        $stream = new \CBOR\StringStream($attestation_raw);
        $attestation_map = (new \CBOR\Decoder())->decode($stream);
        
        \Log::debug('get_data_for_register: Parsed CBOR attestation map', [
            'attestation_map_type' => get_class($attestation_map),
        ]);

        // Convert CBOR map to array
        if ($attestation_map instanceof \CBOR\MapObject) {
            $attestation_array = [];
            foreach ($attestation_map as $key => $value) {
                $attestation_array[$key] = $value;
            }
        } else {
            throw new \RuntimeException('Invalid attestation object format');
        }

        if (!isset($attestation_array['authData'])) {
            \Log::error('get_data_for_register: Missing authData in attestation map');
            throw new \RuntimeException('Malformed attestationObject: missing authData');
        }

        $auth_data = $attestation_array['authData'];
        if ($auth_data instanceof \CBOR\ByteStringObject) {
            $auth_data = $auth_data->getValue();
        }
        
        \Log::debug('get_data_for_register: Extracted authData', [
            'auth_data_length' => strlen($auth_data),
        ]);

        $parsed = $this->parse_auth_data($auth_data);
        \Log::debug('get_data_for_register: Parsed auth data', [
            'credential_id_length' => strlen($parsed['credential_id']),
            'public_key_cbor_length' => strlen($parsed['public_key_cbor']),
        ]);

        $result = [
            'credential_id' => base64_encode($parsed['credential_id']),
            'public_key' => base64_encode($parsed['public_key_cbor']),
        ];

        \Log::debug('get_data_for_register: Completed successfully', $result);

        return $result;
    }

    public function verify(
        string $client_data_json,
        string $authenticator_data,
        string $signature,
        string $public_key
    ): void {
        \Log::debug('verify: Starting', [
            'client_data_json_length' => strlen($client_data_json),
            'authenticator_data_length' => strlen($authenticator_data),
            'signature_length' => strlen($signature),
            'public_key_length' => strlen($public_key),
        ]);

        $client_data = json_decode(base64_decode($client_data_json), true);
        \Log::debug('verify: Decoded client data', [
            'client_data' => $client_data,
        ]);

        $this->validate_client_data($client_data, 'webauthn.get');
        \Log::debug('verify: Client data validated');

        $auth_data = $this->decode_base64_url($authenticator_data);
        \Log::debug('verify: Decoded authenticator data', [
            'auth_data_length' => strlen($auth_data),
        ]);

        $signature = $this->decode_base64_url($signature);
        \Log::debug('verify: Decoded signature', [
            'signature_length' => strlen($signature),
        ]);

        $client_data_hash = hash('sha256', base64_decode($client_data_json), true);
        \Log::debug('verify: Generated client data hash', [
            'hash_length' => strlen($client_data_hash),
        ]);

        $signed_data = $auth_data . $client_data_hash;
        \Log::debug('verify: Constructed signed data', [
            'signed_data_length' => strlen($signed_data),
        ]);

        // Use COSE library to parse the public key
        $cose = base64_decode($public_key);
        
        // First decode CBOR to get the array representation
        $stream = new \CBOR\StringStream($cose);
        $coseData = (new \CBOR\Decoder())->decode($stream);
        
        // Helper function to convert CBOR objects to primitive values
        $convertCborValue = function($value) use (&$convertCborValue) {
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
                if (!is_scalar($value) && !is_null($value)) {
                    \Log::warning('verify: Unknown CBOR type encountered', [
                        'type' => is_object($value) ? get_class($value) : gettype($value),
                        'value' => 'non-scalar'
                    ]);
                }
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
                    // Fallback for unexpected structure
                    \Log::warning('verify: Unexpected item in MapObject', [
                        'type' => is_object($mapItem) ? get_class($mapItem) : gettype($mapItem),
                    ]);
                    continue;
                }
                
                // Log any remaining CBOR objects
                if (is_object($key)) {
                    \Log::error('verify: Key is still an object after conversion', [
                        'key_type' => get_class($key),
                    ]);
                }
                if (is_object($value)) {
                    \Log::error('verify: Value is still an object after conversion', [
                        'key' => $key,
                        'value_type' => get_class($value),
                    ]);
                }
                
                $coseArray[$key] = $value;
            }
            
            \Log::debug('verify: Converted COSE array', [
                'keys' => array_keys($coseArray),
                'value_types' => array_map(function($v) {
                    return is_object($v) ? get_class($v) : gettype($v);
                }, $coseArray),
            ]);
        } else {
            throw new \RuntimeException('Invalid COSE key format');
        }
        
        $coseKey = \Cose\Key\Key::create($coseArray);
        
        \Log::debug('verify: Decoded COSE key', [
            'key_type' => $coseKey->type(),
            'algorithm' => $coseKey->alg(),
        ]);

        // Convert COSE key to PEM format for OpenSSL verification
        $algId = $coseKey->alg();
        
        switch ($algId) {
            case -7:  // ES256 (ECDSA with P-256 and SHA-256)
                // Extract x and y coordinates from COSE key
                $x = $coseKey->get(-2); // x coordinate
                $y = $coseKey->get(-3); // y coordinate
                
                if (!$x || !$y) {
                    throw new \RuntimeException('Missing EC coordinates in COSE key');
                }
                
                // Build uncompressed EC public key (0x04 + x + y)
                $publicKeyBin = "\x04" . $x . $y;
                
                // Create PEM format for EC P-256 key
                $der = $this->createEcP256Der($publicKeyBin);
                $pem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----";
                $opensslAlgo = OPENSSL_ALGO_SHA256;
                break;
                
            case -257: // RS256 (RSASSA-PKCS1-v1_5 with SHA-256)
                // Extract n (modulus) and e (exponent) from COSE key
                $n = $coseKey->get(-1); // modulus
                $e = $coseKey->get(-2); // exponent
                
                if (!$n || !$e) {
                    throw new \RuntimeException('Missing RSA parameters in COSE key');
                }
                
                // Create PEM format for RSA key
                $der = $this->createRsaDer($n, $e);
                $pem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----";
                $opensslAlgo = OPENSSL_ALGO_SHA256;
                break;
                
            default:
                throw new \RuntimeException("Unsupported algorithm: {$algId}");
        }
        
        \Log::debug('verify: Converted COSE to PEM');

        $ok = openssl_verify($signed_data, $signature, $pem, $opensslAlgo);
        \Log::debug('verify: OpenSSL verification result', [
            'result' => $ok,
        ]);

        if ($ok !== 1) {
            \Log::error('verify: Invalid signature');
            throw new \RuntimeException('Invalid signature');
        }

        \Log::debug('verify: Verification successful');
    }

    public function generate_challenge(): string
    {
        $length = config('passkey.challenge_length', 32);
        return rtrim(strtr(base64_encode(random_bytes($length)), '+/', '-_'), '=');
    }

    public function decode_base64_url(string $input): string
    {
        $input .= str_repeat('=', (4 - strlen($input) % 4) % 4);
        return base64_decode(strtr($input, '-_', '+/'), true);
    }

    public function validate_client_data(array $client_data, string $expected_type): void
    {
        if (!isset($client_data['type'], $client_data['challenge'], $client_data['origin'])) {
            throw new \InvalidArgumentException('Malformed client data');
        }

        if ($client_data['type'] !== $expected_type) {
            throw new \InvalidArgumentException("Unexpected clientData type: {$client_data['type']}");
        }
    }

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

    public function get_challenge_from_client_data_json(string $client_data_json): string
    {
        $client_data = json_decode(base64_decode($client_data_json), true);
        $challenge = base64_decode(strtr($client_data['challenge'], '-_', '+/'));

        return rtrim(strtr(base64_encode($challenge), '+/', '-_'), '=');
    }

    /**
     * Create DER-encoded EC P-256 public key
     */
    private function createEcP256Der(string $publicKey): string
    {
        // EC P-256 OID: 1.2.840.10045.3.1.7
        $oid = "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07";
        
        // Algorithm identifier for EC public key
        $algId = "\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01" . $oid;
        
        // Bit string containing the public key
        $bitString = "\x03" . chr(strlen($publicKey) + 1) . "\x00" . $publicKey;
        
        // Complete SEQUENCE
        $der = $algId . $bitString;
        return "\x30" . chr(strlen($der)) . $der;
    }

    /**
     * Create DER-encoded RSA public key
     */
    private function createRsaDer(string $modulus, string $exponent): string
    {
        // Encode integer with DER format
        $encodeInt = function($int) {
            // Add leading zero if high bit is set
            if (ord($int[0]) & 0x80) {
                $int = "\x00" . $int;
            }
            return "\x02" . self::encodeDerLength(strlen($int)) . $int;
        };
        
        // RSA public key SEQUENCE (modulus + exponent)
        $rsaKey = $encodeInt($modulus) . $encodeInt($exponent);
        $rsaKeySeq = "\x30" . self::encodeDerLength(strlen($rsaKey)) . $rsaKey;
        
        // Bit string
        $bitString = "\x03" . self::encodeDerLength(strlen($rsaKeySeq) + 1) . "\x00" . $rsaKeySeq;
        
        // Algorithm identifier for RSA
        $algId = "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00";
        
        // Complete SEQUENCE
        $der = $algId . $bitString;
        return "\x30" . self::encodeDerLength(strlen($der)) . $der;
    }

    /**
     * Encode DER length field
     */
    private static function encodeDerLength(int $length): string
    {
        if ($length < 128) {
            return chr($length);
        }
        
        $encoded = '';
        while ($length > 0) {
            $encoded = chr($length & 0xff) . $encoded;
            $length >>= 8;
        }
        
        return chr(0x80 | strlen($encoded)) . $encoded;
    }

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
        
        // Debug logging
        \Log::debug('Passkey Registration Data', [
            'passkey_id' => $passkey->id,
            'user_id' => $passkey->user_id,
            'challenge' => $challenge,
            'credential_id' => $parsed['credential_id'],
            'public_key' => $parsed['public_key'],
            'raw_id' => $validated['rawId'],
            'id' => $validated['id'],
        ]);

        return $passkey;
    }

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
        
        \Log::debug('verifyPasskey: Searching for passkey', [
            'credential_id_base64url' => $credentialIdBase64Url,
            'credential_id_base64' => $credentialIdBase64,
        ]);
        
        // Find the passkey by credential_id (base64 standard format)
        $passkey = Passkey::where('credential_id', $credentialIdBase64)->first();
        
        if (!$passkey) {
            \Log::warning('verifyPasskey: Passkey not found', [
                'searched_credential_id' => $credentialIdBase64,
            ]);
            
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
