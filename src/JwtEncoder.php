<?php


namespace Phore\JWT;


use InvalidArgumentException;

class JwtEncoder
{
    /**
     * Signing or encryption algorithm as specified in https://tools.ietf.org/html/rfc7518#section-3
     * @var string
     */
    private $alg;
    /**
     * Callback function that performs the signing operation and returns the unencoded signature
     * @var callable
     */
    private $signatureCallback;
    /**
     * The secret used to perform the signing operation
     * @var string
     */
    private $secret;

    /**
     * Signs and encodes the JWT object into the JWS / JWE Compact Serialization. Requires a signing algorithm and
     * secret set through JwtEncoder->setSecret($alg, $secret).
     * If an algorithm was specified in the JWT's 'alg' header, it will be overwritten by the alg provided here.
     *
     * @param Jwt $jwt
     * @return string JWS / JWE Compact Serialization string
     */
    public function encode(Jwt $jwt) : string
    {
        if($this->alg === null)
            throw new InvalidArgumentException("JWT-encoding requires a secret and algorithm to be set.");
        $jwt->setHeader('alg', $this->alg);
        $b64Header = $this->base64urlEncode($jwt->serializeHeader());
        $b64Payload = $this->base64urlEncode($jwt->serializePayload());
        return $this->sign($b64Header . "." . $b64Payload);
    }

    /**
     * Set the secret and algorithm used to sign the JWS or encrypt the JWE token
     *
     * @param string $alg Must be one of the parameters specified in https://tools.ietf.org/html/rfc7518#section-3
     * @param string $secret A valid secret in accordance with the chosen algorithm
     *
     * @throws InvalidArgumentException if any of the supplied parameters are invalid
     */
    public function setSecret(string $alg, string $secret)
    {
        switch ($alg) {
            case 'none':
                if(!empty($secret))
                    throw new InvalidArgumentException("Algorithm 'none' requires an empty secret!");
                $this->signatureCallback = function ($b64HeaderPayload) {
                    return "";
                };
                break;
            case "HS256":
                /**
                 * TODO: Using a PKCS key for symmetric algorithms can be dangerous. This could be prevented here by
                 *  validating the secret
                 */
                $this->signatureCallback = function ($b64HeaderPayload) {
                    return hash_hmac("sha256", $b64HeaderPayload, $this->secret, true);
                };
                break;
            case "HS512":
                /**
                 * TODO: Using a PKCS key for symmetric algorithms can be dangerous. This could be prevented here by
                 *  validating the secret
                 */
            $this->signatureCallback = function ($b64HeaderPayload) {
                    return hash_hmac("sha512", $b64HeaderPayload, $this->secret, true);
                };
                break;
            case "RS256":
                $this->signatureCallback = function ($b64HeaderPayload) {
                    if(!openssl_sign($b64HeaderPayload, $signature, $this->secret, OPENSSL_ALGO_SHA256))
                        throw new InvalidArgumentException("Secret must be a valid PEM-formatted RSA Private Key");
                    return $signature;
                };
                break;
            case "RS512":
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
            default:
                throw new InvalidArgumentException("Algorithm '$alg' unknown or not supported.");
        }

        $this->alg = $alg;
        $this->secret = $secret;
    }


    private function sign(string $b64HeaderPayload) : string
    {
        return $b64HeaderPayload . "." . $this->base64urlEncode(($this->signatureCallback)($b64HeaderPayload));
    }

    private function base64urlEncode(string $string)
    {
        return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($string));
    }


}
