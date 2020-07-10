<?php


namespace Phore\JWT\JWK;


use InvalidArgumentException;

class JwkFactory
{
    /**
     * Generate a JWK from json array
     *
     * @param array $jsonInput
     * @return Jwk
     */
    public function buildJwk(array $jsonInput) : Jwk
    {

    }

    public function loadJwkString(string $json) : Jwk
    {
        //TODO: create a jwk from a jwk json string
        throw new InvalidArgumentException("Invalid or unsupported JWK format.");
    }

    public static function loadPem(string $pemKeyString) : Jwk
    {
        if(!preg_match("/-{5}BEGIN (?:(RSA|EC) )?(PUBLIC|PRIVATE) KEY-{5}/", $pemKeyString, $matches)) {
            throw new InvalidArgumentException("Invalid or unsupported PEM key format.");
        }
        if($matches[2] == "PRIVATE") {
            $key = openssl_pkey_get_private($pemKeyString);
            if($key === false)
                throw new InvalidArgumentException("Invalid or unsupported PEM key format.");
            $keyDetails = openssl_pkey_get_details($key);
            switch ($keyDetails['type']) {
                case OPENSSL_KEYTYPE_RSA:
                    $key = new RsaPrivateKey(
                        $keyDetails["rsa"]["n"],
                        $keyDetails["rsa"]["e"],
                        $keyDetails["rsa"]["d"],
                        $keyDetails["rsa"]["p"],
                        $keyDetails["rsa"]["q"],
                        $keyDetails["rsa"]["dmp1"],
                        $keyDetails["rsa"]["dmq1"],
                        $keyDetails["rsa"]["iqmp"]
                    );
                    $key->setPemEncodedString($pemKeyString);
                    return $key;
                case OPENSSL_KEYTYPE_DSA:
                case OPENSSL_KEYTYPE_DH:
                case OPENSSL_KEYTYPE_EC:
                    throw new InvalidArgumentException("Key Type currently not supported");
                default:
                    throw new InvalidArgumentException("Unknown Key Type");
            }
        } else {
            $key = openssl_pkey_get_public($pemKeyString);
            if($key === false)
                throw new InvalidArgumentException("Invalid or unsupported PEM key format.");
            $keyDetails = openssl_pkey_get_details($key);
            switch ($keyDetails['type']) {
                case OPENSSL_KEYTYPE_RSA:
                    $key = new RsaPublicKey($keyDetails["rsa"]["n"], $keyDetails["rsa"]["e"]);
                    $key->setPemEncodedString($pemKeyString);
                    return $key;
                case OPENSSL_KEYTYPE_DSA:
                case OPENSSL_KEYTYPE_DH:
                case OPENSSL_KEYTYPE_EC:
                    throw new InvalidArgumentException("Key Type currently not supported");
                default:
                    throw new InvalidArgumentException("Unknown Key Type");
            }
        }
    }

    public function loadJwk(string $jwkString)
    {
//        $success = true;
//        $keyParams = json_decode($jwkString);
//        if(!key_exists('kty', $keyParams))
//            throw new InvalidArgumentException("Invalid or unsupported JSON Web Key format.");
//        $keyParams['kty'];

    }

    public function createJwk(string $alg) : Jwk
    {
        //TODO: create a new jwk with supplied algorithm
        throw new InvalidArgumentException("Invalid or unsupported algorithm.");
    }

}
