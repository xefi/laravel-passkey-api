<?php

namespace Xefi\LaravelPasskey\Webauthn;

use Xefi\LaravelPasskey\Exceptions\MissingEcCoordinatesException;
use Xefi\LaravelPasskey\Exceptions\MissingRsaParametersException;

/**
 * COSE algorithm identifiers supported for WebAuthn passkey verification.
 *
 * Each case maps to a COSE algorithm ID as defined in RFC 8152 § 8.1
 * and exposes the logic to build an OpenSSL-compatible PEM from a parsed COSE key.
 *
 * References:
 * - COSE Algorithm Identifiers: https://www.rfc-editor.org/rfc/rfc8152.html#section-8.1
 * - IANA COSE Algorithms Registry: https://www.iana.org/assignments/cose/cose.xhtml
 */
enum Algorithm: int
{
    /**
     * ECDSA with P-256 and SHA-256 (COSE algorithm ID: -7)
     */
    case ES256 = -7;

    /**
     * RSASSA-PKCS1-v1_5 with SHA-256 (COSE algorithm ID: -257)
     */
    case RS256 = -257;

    /**
     * Build an OpenSSL-compatible PEM public key from a parsed COSE key.
     *
     * @param \Cose\Key\Key $coseKey Parsed COSE key
     * @return array{pem: string, opensslAlgo: int}
     * @throws MissingEcCoordinatesException
     * @throws MissingRsaParametersException
     */
    public function buildPem(\Cose\Key\Key $coseKey): array
    {
        return match ($this) {
            self::ES256 => $this->buildEs256Pem($coseKey),
            self::RS256 => $this->buildRs256Pem($coseKey),
        };
    }

    /**
     * Build PEM for ES256 (ECDSA P-256 / SHA-256).
     *
     * Extracts the x and y coordinates from the COSE key, assembles the uncompressed
     * EC point (0x04 + x + y), and returns a SubjectPublicKeyInfo PEM string.
     *
     * References:
     * - SEC1 § 2.3.3: https://www.secg.org/sec1-v2.pdf
     * - RFC 5480: https://www.rfc-editor.org/rfc/rfc5480.html
     *
     * @throws MissingEcCoordinatesException If x or y coordinate is absent
     */
    private function buildEs256Pem(\Cose\Key\Key $coseKey): array
    {
        $x = $coseKey->get(-2); // x coordinate
        $y = $coseKey->get(-3); // y coordinate

        if (!$x || !$y) {
            throw new MissingEcCoordinatesException();
        }

        // Build uncompressed EC public key (0x04 + x + y)
        $publicKeyBin = "\x04" . $x . $y;

        // EC P-256 OID: 1.2.840.10045.3.1.7
        $oid = "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07";
        $algId = "\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01" . $oid;
        $bitString = "\x03" . chr(strlen($publicKeyBin) + 1) . "\x00" . $publicKeyBin;
        $der = $algId . $bitString;
        $der = "\x30" . chr(strlen($der)) . $der;

        return [
            'pem' => $this->derToPem($der),
            'opensslAlgo' => OPENSSL_ALGO_SHA256,
        ];
    }

    /**
     * Build PEM for RS256 (RSASSA-PKCS1-v1_5 / SHA-256).
     *
     * Extracts the modulus and exponent from the COSE key and returns a
     * SubjectPublicKeyInfo PEM string.
     *
     * References:
     * - RFC 8017 § A.1.1: https://www.rfc-editor.org/rfc/rfc8017.html#appendix-A.1.1
     * - RFC 5280 § 4.1: https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1
     *
     * @throws MissingRsaParametersException If modulus or exponent is absent
     */
    private function buildRs256Pem(\Cose\Key\Key $coseKey): array
    {
        $n = $coseKey->get(-1); // modulus
        $e = $coseKey->get(-2); // exponent

        if (!$n || !$e) {
            throw new MissingRsaParametersException();
        }

        $encodeInt = static function (string $int): string {
            if (ord($int[0]) & 0x80) {
                $int = "\x00" . $int;
            }
            return "\x02" . self::encodeDerLength(strlen($int)) . $int;
        };

        $rsaKey = $encodeInt($n) . $encodeInt($e);
        $rsaKeySeq = "\x30" . self::encodeDerLength(strlen($rsaKey)) . $rsaKey;
        $bitString = "\x03" . self::encodeDerLength(strlen($rsaKeySeq) + 1) . "\x00" . $rsaKeySeq;
        $algId = "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00";
        $der = $algId . $bitString;
        $der = "\x30" . self::encodeDerLength(strlen($der)) . $der;

        return [
            'pem' => $this->derToPem($der),
            'opensslAlgo' => OPENSSL_ALGO_SHA256,
        ];
    }

    /**
     * Wrap a DER-encoded key in PEM armor.
     */
    private function derToPem(string $der): string
    {
        return "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(base64_encode($der), 64, "\n")
            . "-----END PUBLIC KEY-----";
    }

    /**
     * Encode a DER length field (short form < 128, long form >= 128).
     *
     * References:
     * - X.690 § 8.1.3: https://www.itu.int/rec/T-REC-X.690/
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
}
