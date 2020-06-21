<?php


namespace Phore\JWT;


use Phore\App\Mod\OAuth\PublicKeyConverter;
use Phore\Core\Exception\InvalidDataException;

class JwtDecoder
{


    /**
     * @var callable|null
     */
    private $publicKeyLoader = null;


    public function setPublicKeyLoader(callable $cb)
    {
        $this->publicKeyLoader = $cb;
    }


    public function decode(string $tokenData)
    {

        $unverifiedToken = $this->_decodeStrToken($tokenData);


        if ($this->publicKeyLoader !== null) {
            $this->addPublicKey(($this->publicKeyLoader)($unverifiedToken));
        }


        $verifiedToken = $this->_verifyConstraints($unverifiedToken);

        return $verifiedToken;

    }

    private function validateSignature(string $tokenString)
    {
        $tokenComponents = explode(".", $tokenString);
        if(count($tokenComponents) !== 3) {
            throw new \InvalidArgumentException("Malformed or unsupported Jwt");
        }
        $header = phore_json_decode(base64_decode($tokenComponents[0]));
        $data = $tokenComponents[0].".".$tokenComponents[1];
        $signature = base64_decode(str_replace(['-', '_', ''], ['+', '/', '='], $tokenComponents[2]));

        $headerAlg = phore_pluck('alg', $header, new \InvalidArgumentException("Invalid token header: alg missing."));

        switch ($headerAlg) {
            case "HS256":
                $hash = hash_hmac("sha256", $data, $this->clientSecret, true);
                if(hash_equals($signature, hash_hmac("sha256", $data, $this->clientSecret, true))) {
                    return true;
                }
                return false;
            case "HS512":
                if(hash_equals($signature, hash_hmac("sha512", $data, $this->clientSecret, true))) {
                    return true;
                }
                return false;
            case "RS256":
                $rsaSignatureAlg = OPENSSL_ALGO_SHA256;
                break;
            case "RS512":
                $rsaSignatureAlg = OPENSSL_ALGO_SHA512;
                break;
            default:
                throw new \InvalidArgumentException("Unsupported signing method: $headerAlg");
        }

        $jwks = phore_http_request($this->config['jwks_uri'])->send()->getBodyJson();

        $keyFound = false;
        foreach ($jwks as $index => $key) {
            $kid = phore_pluck('kid', $key);
            if($kid === $header['kid']) {
                $keyFound = true;
                break;
            }
        }

        if(!$keyFound) {
            throw new InvalidDataException("No matching kid found in JWKS");
        }

        $jwk = $jwks[$index];

        if(phore_pluck('alg', $jwk, new \InvalidArgumentException("Invalid jwk: alg missing.")) !== $headerAlg) {
            throw new InvalidDataException("Signing Algorithms jwks: {$jwks[$index]['alg']} and jwt: $headerAlg don't match.");
        }

        $modulo = phore_pluck('n',$jwk, new \InvalidArgumentException("Invalid jwk: n missing."));
        $exponent = phore_pluck('e',$jwk, new \InvalidArgumentException("Invalid jwk: e missing."));

        $converter = new PublicKeyConverter();
        $pubKey = $converter->getPemPublicKeyFromModExp($modulo, $exponent);
        $pub = openssl_pkey_get_public($pubKey);

        $verify = openssl_verify($data, $signature, $pub, $rsaSignatureAlg);
        return filter_var($verify, FILTER_VALIDATE_BOOLEAN);

    }


}
