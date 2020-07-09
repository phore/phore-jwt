<?php


namespace Phore\JWT;


use Phore\App\Mod\OAuth\PublicKeyConverter;
use Phore\Core\Exception\InvalidDataException;

class JwtDecoderOld
{

    /**
     * @var bool Set to true to allow decoding unsecured jws
     */
    private $allowUnsecuredJws = false;

    private $singleSecret;
    private $singleAlg;

    /**
     * @var callable|null
     */
    private $publicKeyLoader = null;


    public function setPublicKeyLoader(callable $cb)
    {
        $this->publicKeyLoader = $cb;
    }

    public function setAllowUnsecuredJws(bool $allow)
    {
        $this->allowUnsecuredJws = $allow;
    }

    public function setSingleSecret(string $alg, string $secret)
    {
        if(!Jwa::isValid($alg))
            throw new \InvalidArgumentException("Algorithm '$alg' must be a valid JWA");
        $this->singleAlg = $alg;
        $this->singleSecret = $secret;
    }

    public function decode(string $tokenString) : Jwt
    {
        // has a secret and algorithm been defined? If not, don't allow encoding
        if(!isset($this->singleAlg) && !isset($this->singleSecret))
            throw new \InvalidArgumentException("Cannot decode token: No key available.");
        $jwtParts = explode(".", $tokenString);
        // does it look like a jwt??
        if(count($jwtParts) < 3)
            throw new \UnexpectedValueException("Token '" . substr($tokenString, 0, 9) . "...' is not a valid JWT.");
        if(empty($jwtParts[2])) {
            //this is an unsecured JWS
            if(!$this->allowUnsecuredJws)
                throw new \Exception("Unsecured JWS is not allowed.");
            return $this->decodeJws($tokenString);
        }
        if(count($jwtParts) == 3) {
            //this looks like JWS, lets try to decode the header and do some more validation
            if(!$this->validateSignature($this->singleAlg, $this->singleSecret, $tokenString))
                throw new \UnexpectedValueException("Invalid Signature.");
            return $this->decodeJws($tokenString);

        }


//        $unverifiedToken = $this->_decodeStrToken($tokenData);

//
//        if ($this->publicKeyLoader !== null) {
//            $this->addPublicKey(($this->publicKeyLoader)($unverifiedToken));
//        }
//
//
//        $verifiedToken = $this->_verifyConstraints($unverifiedToken);
//
//        return $verifiedToken;

    }

    private function decodeJws(string $tokenString) : Jwt
    {
        $jwtParts = explode(".", $tokenString);
        $header = json_decode($this->base64urlDecode($jwtParts[0]), true);
        $payload = json_decode($this->base64urlDecode($jwtParts[1]), true);
        $jwt = new Jwt($payload);
        foreach ($header as $key => $val) {
            $jwt->setHeader($key, $val);
        }
        return $jwt;
    }

    private function base64urlDecode(string $string)
    {
        $decodedString = base64_decode(str_replace(['-', '_', ''], ['+', '/', '='], $string), true);
        if($decodedString === false)
            throw new \UnexpectedValueException("String contains invalid base64 characters.");
        return $decodedString;
    }

    private function validateSignature(string $alg, string $secret, string $tokenString)
    {
        $jwtParts = explode(".", $tokenString);
        $header = json_decode($this->base64urlDecode($jwtParts[0]), true);
        $alg = $header['alg'] ?? "not specified";
        if($alg !== $this->singleAlg)
            throw new \UnexpectedValueException("Algorithm '$alg' is not supported.");
        $signature = $this->base64urlDecode($jwtParts[2]);
        $data = $jwtParts[0] . "." . $jwtParts[1];
        switch ($alg) {
            case Jwa::HS256:
                if(hash_equals($signature, hash_hmac("sha256", $data, $this->singleSecret, true))) {
                    return true;
                }
                return false;
            case Jwa::HS512:
                if(hash_equals($signature, hash_hmac("sha512", $data, $this->singleSecret, true))) {
                    return true;
                }
                return false;
            case Jwa::RS256:
                $verify = openssl_verify($data, $signature, $this->singleSecret, OPENSSL_ALGO_SHA256);
                return filter_var($verify, FILTER_VALIDATE_BOOLEAN);
                break;
            case Jwa::RS512:
                $verify = openssl_verify($data, $signature, $this->singleSecret, OPENSSL_ALGO_SHA512);
                return filter_var($verify, FILTER_VALIDATE_BOOLEAN);
                break;
            default:
                throw new \InvalidArgumentException("Unsupported JWA: '$alg'");
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
