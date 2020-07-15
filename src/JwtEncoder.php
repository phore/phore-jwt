<?php


namespace Phore\JWT;


use InvalidArgumentException;
use Phore\JWT\JWK\Jwk;
use Phore\JWT\JWK\Jwks;

class JwtEncoder
{
    /**
     * Callback function that performs the signing operation and returns the unencoded signature
     * @var callable
     */
    private $signatureCallback;

    /**
     * @var string $secret
     */
    private $secret;

    /**
     * @var Jwks $jwkSet
     */
    private $jwkSet;

    /**
     * JwtEncoder constructor.
     * @param Jwks|null $jwkSet
     */
    public function __construct()
    {
        $this->jwkSet = new Jwks();
    }

    public function setJwks(Jwks $jwkSet)
    {
        $this->jwkSet = $jwkSet;
    }

    public function addJwk(Jwk $jwk) : string
    {
        return $this->jwkSet->addJwk($jwk);
    }

    /**
     * Signs and encodes the JWT object into the JWS / JWE Compact Serialization. Requires a signing algorithm and
     * secret set by adding a jwk key using addJwk($key). If an algorithm was specified in the JWT's 'alg' header,
     * it will be overwritten by the alg of the key.
     *
     * @param Jwt $jwt
     * @param string $kid References a key in the jwks
     * @return string JWS / JWE Compact Serialization string
     */
    public function encode(Jwt $jwt, string $kid) : string
    {
        $key = $this->jwkSet->getKey($kid);
        if(empty($key)){
            throw new InvalidArgumentException("Cannot encode token. Key '$kid' not found.");
        }
        $alg = $key->getAlgorithm();
        $jwt->setHeader('alg', $alg);
        $jwt->setHeader('kid', $kid);
        switch ($alg) {
            case 'none':
                // TODO: find a save way to disable alg none
                // throw new InvalidArgumentException("Algorithm 'none' requires an empty secret!");
                $this->signatureCallback = function ($b64HeaderPayload) {
                    return "";
                };
                break;
            case "HS256":
                /**
                 * TODO: Using a PKCS key for symmetric algorithms can be dangerous. This could be prevented here by
                 *  validating the secret
                 */
                $this->secret = $key->getArray()['k'];
                $this->signatureCallback = function ($b64HeaderPayload) {
                    return hash_hmac("sha256", $b64HeaderPayload, $this->secret, true);
                };
                break;
            case "HS512":
                /**
                 * TODO: Using a PKCS key for symmetric algorithms can be dangerous. This could be prevented here by
                 *  validating the secret
                 */
                $this->secret = $key->getArray()['k'];
                $this->signatureCallback = function ($b64HeaderPayload) {
                    return hash_hmac("sha512", $b64HeaderPayload, $this->secret, true);
                };
                break;
            case Jwa::RS256:
                $this->secret = $key->getPem();
                $this->signatureCallback = function ($b64HeaderPayload) {
                    if(!openssl_sign($b64HeaderPayload, $signature, $this->secret, OPENSSL_ALGO_SHA256))
                        throw new InvalidArgumentException("Secret must be a valid PEM-formatted RSA Private Key");
                    return $signature;
                };
                break;
            case "RS512":
                $this->secret = $key->getPem();
                $this->signatureCallback = function ($b64HeaderPayload) {
                    if(!openssl_sign($b64HeaderPayload, $signature, $this->secret, OPENSSL_ALGO_SHA512))
                        throw new InvalidArgumentException("Secret must be a valid PEM-formatted RSA Private Key");
                    return $signature;
                };
                break;
            case "RS384":
            case "ES256":
            case "ES384":
            case "ES512":
            case "PS256":
            case "PS384":
            case "PS512":
                throw new InvalidArgumentException("Algorithm '$alg' not supported.");
            default:
                throw new InvalidArgumentException("JWT-encoding requires a secret and algorithm to be set.");
        }
        $b64Header = $this->base64urlEncode($jwt->serializeHeader());
        $b64Payload = $this->base64urlEncode($jwt->serializePayload());
        return $this->sign($b64Header . "." . $b64Payload);
    }

    private function sign(string $b64HeaderPayload) : string
    {
        return $b64HeaderPayload . "." . $this->base64urlEncode(($this->signatureCallback)($b64HeaderPayload));
    }

    private function base64urlEncode(string $string)
    {
        return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($string));
    }

    private function validateKey(Jwk $jwk) {
        if(empty($jwk->getAlgorithm()))
            throw new InvalidArgumentException("Jwk must be assigned an algorithm.");
    }


}
