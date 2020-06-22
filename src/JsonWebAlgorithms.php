<?php


namespace Phore\JWT;


use ReflectionClass;

class JsonWebAlgorithms
{
    /**
     * Parameter Values for JWS as specified in:
     * https://tools.ietf.org/html/rfc7518#section-3.1
     */
    public const HS256 = 'HS256'; // HMAC using SHA-256
    public const HS384 = 'HS384'; // HMAC using SHA-384
    public const HS512 = 'HS512'; // HMAC using SHA-512
    public const RS256 = 'RS256'; // RSASSA-PKCS1-v1_5 using SHA-256
    public const RS384 = 'RS384'; // RSASSA-PKCS1-v1_5 using SHA-384
    public const RS512 = 'RS512'; // RSASSA-PKCS1-v1_5 using SHA-512
    public const ES256 = 'ES256'; // ECDSA using P-256 and SHA-256
    public const ES384 = 'ES384'; // ECDSA using P-256 and SHA-384
    public const ES512 = 'ES512'; // ECDSA using P-256 and SHA-512
    public const PS256 = 'PS256'; // RSASSA-PSS using SHA-256 and MGF1 with SHA-256
    public const PS384 = 'PS384'; // RSASSA-PSS using SHA-384 and MGF1 with SHA-384
    public const PS512 = 'PS512'; // RSASSA-PSS using SHA-512 and MGF1 with SHA-512
    public const NONE = 'none'; // No digital signature or MAC performed

    /**
     * Parameter Values for JWE as specified in:
     * https://tools.ietf.org/html/rfc7518#section-4.1
     */
    public const RSA1_5 = 'RSA1_5';
    public const RSA_OAEP = 'RSA-OAEP';
    public const RSA_OAEP_256 = 'RSA-OAEP-256';
    public const A128KW = 'A128KW';
    public const A192KW = 'A192KW';
    public const A256KW = 'A256KW';
    public const DIR = 'dir';
    public const ECDH_ES = 'ECDH-ES';
    public const ECDH_ES_A128KW = 'ECDH-ES+A128KW';
    public const ECDH_ES_A192KW = 'ECDH-ES+A192KW';
    public const ECDH_ES_A256KW = 'ECDH-ES+A256KW';
    public const A128GCMKW = 'A128GCMKW';
    public const A192GCMKW = 'A192GCMKW';
    public const A256GCMKW = 'A256GCMKW';
    public const PBES2_HS256_A128KW = 'PBES2-HS256+A128KW';
    public const PBES2_HS384_A192KW = 'PBES2-HS384+A192KW';
    public const PBES2_HS512_A256KW = 'PBES2-HS512+A256KW';

    public static function isValid(string $alg)
    {
        $refl = new ReflectionClass('Phore\JWT\JsonWebAlgorithms');
        return in_array($alg, $refl->getconstants());
    }

}
