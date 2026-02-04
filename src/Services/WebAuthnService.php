<?php

namespace Xefi\LaravelPasskey\Services;

use Xefi\LaravelPasskey\Models\Passkey;

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
                ['type' => 'public-key', 'alg' => -7],
                ['type' => 'public-key', 'alg' => -257],
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

    public function get_data_for_register(string $client_data_json, string $attestation_object): array
    {
        $this->validate_client_data($client_data, 'webauthn.create');

        $attestation_raw = $this->decode_base64_url($attestation_object);

        $stream = new \CBOR\StringStream($attestation_raw);
        $attestation_map = (new \CBOR\Decoder())->decode($stream);

        if ($attestation_map instanceof \CBOR\MapObject) {
            $attestation_array = [];
            foreach ($attestation_map as $key => $value) {
                $attestation_array[$key] = $value;
            }
        } else {
            throw new \RuntimeException('Invalid attestation object format');
        }

        if (!isset($attestation_array['authData'])) {
            throw new \RuntimeException('Malformed attestationObject: missing authData');
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

        $cose = base64_decode($public_key);

        $stream = new \CBOR\StringStream($cose);
        $coseData = (new \CBOR\Decoder())->decode($stream);

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
                return $value;
            }
        };

        if ($coseData instanceof \CBOR\MapObject) {
            $coseArray = [];

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
            throw new \RuntimeException('Invalid COSE key format');
        }

        $coseKey = \Cose\Key\Key::create($coseArray);

        $algId = $coseKey->alg();

        switch ($algId) {
            case -7:
                $x = $coseKey->get(-2);
                $y = $coseKey->get(-3);

                if (!$x || !$y) {
                    throw new \RuntimeException('Missing EC coordinates in COSE key');
                }

                $publicKeyBin = "\x04" . $x . $y;

                $der = $this->createEcP256Der($publicKeyBin);
                $pem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----";
                $opensslAlgo = OPENSSL_ALGO_SHA256;
                break;

            case -257:
                $n = $coseKey->get(-1);
                $e = $coseKey->get(-2);

                if (!$n || !$e) {
                    throw new \RuntimeException('Missing RSA parameters in COSE key');
                }

                $der = $this->createRsaDer($n, $e);
                $pem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----";
                $opensslAlgo = OPENSSL_ALGO_SHA256;
                break;

            default:
                throw new \RuntimeException("Unsupported algorithm: {$algId}");
        }

        $ok = openssl_verify($signed_data, $signature, $pem, $opensslAlgo);

        if ($ok !== 1) {
            throw new \RuntimeException('Invalid signature');
        }
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
        $oid = "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07";

        $algId = "\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01" . $oid;

        $bitString = "\x03" . chr(strlen($publicKey) + 1) . "\x00" . $publicKey;

        $der = $algId . $bitString;
        return "\x30" . chr(strlen($der)) . $der;
    }

    /**
     * Create DER-encoded RSA public key
     */
    private function createRsaDer(string $modulus, string $exponent): string
    {
        $encodeInt = function ($int) {
            if (ord($int[0]) & 0x80) {
                $int = "\x00" . $int;
            }
            return "\x02" . self::encodeDerLength(strlen($int)) . $int;
        };

        $rsaKey = $encodeInt($modulus) . $encodeInt($exponent);
        $rsaKeySeq = "\x30" . self::encodeDerLength(strlen($rsaKey)) . $rsaKey;

        $bitString = "\x03" . self::encodeDerLength(strlen($rsaKeySeq) + 1) . "\x00" . $rsaKeySeq;

        $algId = "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00";

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
        $challenge = $this->get_challenge_from_client_data_json(
            $validated['response']['clientDataJSON']
        );

        $parsed = $this->get_data_for_register(
            $validated['response']['clientDataJSON'],
            $validated['response']['attestationObject']
        );

        $passkey = Passkey::create([
            'user_id' => $userId,
            'label' => $validated['label'] ?? 'Default Passkey',
            'credential_id' => $parsed['credential_id'],
            'challenge' => $challenge,
            'public_key' => $parsed['public_key'],
        ]);

        return $passkey;
    }

    public function verifyPasskey(string $credentialIdBase64Url, array $response): Passkey
    {
        $credentialIdBase64 = str_pad(
            strtr($credentialIdBase64Url, '-_', '+/'),
            strlen($credentialIdBase64Url) + (4 - strlen($credentialIdBase64Url) % 4) % 4,
            '=',
            STR_PAD_RIGHT
        );

        $passkey = Passkey::where('credential_id', $credentialIdBase64)->first();

        if (!$passkey) {
            throw new \Exception('Passkey not found');
        }

        $this->verify(
            $response['clientDataJSON'],
            $response['authenticatorData'],
            $response['signature'],
            $passkey->public_key
        );

        return $passkey;
    }
}
