<?php


namespace Phore\JWT;

use Phore\JWT\Exceptions\InvalidAlgorithmException;
use Phore\JWT\Exceptions\InvalidClaimException;
use Phore\JWT\Exceptions\InvalidHeaderException;
use Phore\JWT\Exceptions\InvalidJwtFormatException;
use Phore\JWT\Exceptions\InvalidSignatureException;
use Phore\JWT\JWK\Jwk;
use Phore\JWT\JWK\Jwks;
use stdClass;

/**
 * Class JwsDecoder
 * @package Phore\JWT
 *
 * Validates and decodes a JWS Token
 */
class JwsDecoder
{
    // validation parameters
    /**
     * @var string URL of the issuing party
     */
    private $issuer;
    /**
     * @var string ClientId that is registered at issuer
     */
    private $clientId;

    /**
     * @var string $clientSecret Secret of the client used for symmetric algorithms HS256 and HS512
     */
    private $clientSecret;
    /**
     * @var array ClientIds that must present int the 'aud' claim (in addition to the clientId specified above)
     */
    private $audience;
    /**
     * @var array Array of claims that must be present
     */
    private $requiredClaims;
    /**
     * @var array Associative array of claims and values they must contain
     */
    private $requiredClaimsContain;
    /**
     * @var array Associative array of claims and values they must have
     */
    private $requiredClaimsEqual;

    /**
     * @var Jwks JWKS Class Object containing one ore more keys used for signature validation
     */
    private $jwkSet;

    private $additionalHeaders;

    private $header;
    private $payload;
    private $signature;

    private $nested = false;

    /**
     * JwsDecoder constructor.
     */
    public function __construct()
    {
        $this->jwkSet = new Jwks();
        $this->additionalHeaders = [];
        $this->requiredClaims = [];
        $this->requiredClaimsContain = [];
        $this->requiredClaimsEqual = [];
    }

    // Validation Settings

    /**
     * @param string $issuer
     */
    public function setIssuer(string $issuer): void
    {
        $this->issuer = $issuer;
    }

    /**
     * @param string $clientId
     */
    public function setClientId(string $clientId): void
    {
        $this->clientId = $clientId;
    }

    /**
     * @param string $clientSecret
     */
    public function setClientSecret(string $clientSecret): void
    {
        $this->clientSecret = $clientSecret;
    }

    /**
     * @param array $requiredClaims
     */
    public function setRequiredClaims(array $requiredClaims): void
    {
        $this->requiredClaims = $requiredClaims;
    }

    /**
     * @param array $requiredClaimsContain
     */
    public function setRequiredClaimsContain(array $requiredClaimsContain): void
    {
        $this->requiredClaimsContain = $requiredClaimsContain;
    }

    public function setRequiredAudience(array $audience)
    {
        $this->audience = $audience;
    }

    /**
     * Set the JWKS with keys that can be used for signature validation. This will overwrite any previously added keys.
     * @param Jwks $jwkSet
     */
    public function setJwks(Jwks $jwkSet): void
    {
        $this->jwkSet = $jwkSet;
    }

    /**
     * Add a key that can be used for signature validation. Multiple keys are allowed.
     * @param Jwk $jwk
     * @return string KeyId ('kid') of the added key.
     */
    public function addJwk(Jwk $jwk) : string
    {
        return $this->jwkSet->addJwk($jwk);
    }

    /**
     * Whitelist of non-required Headers that might be considered critical by token generator
     * @param array $additionalHeaders
     */
    public function setAdditionalHeaders(array $additionalHeaders): void
    {
        $this->additionalHeaders = $additionalHeaders;
    }


    public function decode(string $jwsToken)
    {
        if(!preg_match("/^([\w-]+)\.([\w-]+)\.([\w-]*)$/", $jwsToken, $jwsComponents))
            throw new InvalidJwtFormatException("JWS needs exactly three base64url-encoded components delimited by two period characters.");
        $this->header = base64urlDecode($jwsComponents[1]);
        $this->payload = base64urlDecode($jwsComponents[2]);
        $header = json_decode($this->header);
        if(!($header instanceof stdClass))
            throw new InvalidJwtFormatException("JWS contains invalid Json.");
        $this->validateHeader($header);
        if($this->nested === true)
            throw new InvalidJwtFormatException("Nested JWTs are currently not supported");
        if(empty($header->kid) && empty($this->clientSecret))
            throw new InvalidSignatureException("No keys provided to validate signature.");
        $this->validateSignature($header->alg, $header->kid ?? $this->clientSecret, $jwsComponents[0].$jwsComponents[1]);
        $claimsSet = json_decode($this->payload, true);
        if(!(is_array($claimsSet)))
            throw new InvalidJwtFormatException("JWS contains invalid Json.");

        $this->validateClaims($claimsSet);

        $jwt = new Jwt($claimsSet);
        foreach ($header as $key => $value) {
            $jwt->setHeader($key, $value);
        }

        return $jwt;

    }

    private function validateAlg($alg)
    {
        return Jwa::isValid($alg);
    }

    private function validateHeader(stdClass $header)
    {
        if(!isset($header->alg) || !$this->validateAlg($header->alg))
            throw new InvalidAlgorithmException("Invalid algorithm '" . ($header->alg ?? 'undefined') . "'.");
        if(isset($header->cty) && strtoupper($header->cty) == 'JWT') {
            $this->nested = true;
        }
        if(isset($header->crit)) {
            foreach($header->crit as $criticalHeader) {
                if(!isset($header->$criticalHeader) || !in_array($criticalHeader, $this->additionalHeaders))
                    throw new InvalidHeaderException("Critical Header parameter '$criticalHeader' is missing or not supported.");
            }
        }
    }

    private function validateSignature(string $tokenAlg, string $tokenKid = '', string $b64headerPayload = '') {
        $jwk = $this->jwkSet->getKey($tokenKid);
        switch ($tokenAlg) {
            case Jwa::HS256:
                return hash_equals($this->signature, hash_hmac("sha256", $b64headerPayload, $jwk->getArray()['k'], true));
            case Jwa::HS512:
                return hash_equals($this->signature, hash_hmac("sha512", $b64headerPayload, $jwk->getArray()['k'], true));
            case Jwa::RS256:
                $rsaSignatureAlg = OPENSSL_ALGO_SHA256;
                $pub = openssl_pkey_get_public($jwk->getPem());
                $verify = openssl_verify($b64headerPayload, $this->signature, $pub, $rsaSignatureAlg);
                return filter_var($verify, FILTER_VALIDATE_BOOLEAN);
            case Jwa::RS512:
                $rsaSignatureAlg = OPENSSL_ALGO_SHA512;
                $pub = openssl_pkey_get_public($jwk->getPem());
                $verify = openssl_verify($b64headerPayload, $this->signature, $pub, $rsaSignatureAlg);
                return filter_var($verify, FILTER_VALIDATE_BOOLEAN);
            default:
                throw new InvalidSignatureException("Signature verification failed.");
        }
    }


    private function validateClaims(array $claimsSet)
    {
        $requiredStandardClaims = ["iss", "aud", "exp", "iat", "sub"];
        foreach ($requiredStandardClaims as $claim) {
            if (!key_exists($claim, $claimsSet)){
                throw new InvalidClaimException("Claim '$claim' missing");
            }
        }
        if($claimsSet['iss'] != $this->issuer) {
            throw new InvalidClaimException("Invalid token issuer (expected {$this->issuer}, given {$claimsSet['iss']})");
        }
        if(is_array($claimsSet['aud'])) {
            $this->audience[] = $this->clientId;
            foreach ($this->audience as $client) {
                if(!in_array($client, $claimsSet['aud'])) {
                    throw new InvalidClaimException("Client '$client' not listed as audience");
                }
            }
        } else if($this->clientId != $claimsSet['aud']) {
            throw new InvalidClaimException("Client '{$this->clientId}' not listed as audience");
        }

        if($claimsSet['exp'] < time()) {
            throw new InvalidClaimException("Token expired");
        }
        if($claimsSet['iat'] > time()) {
            throw new InvalidClaimException("Token looks suspiciously futuristic");
        }

        foreach ($this->requiredClaims as $claim) {
            if (!key_exists($claim, $claimsSet)){
                throw new InvalidClaimException("Claim '$claim' missing");
            }
        }

        foreach ($this->requiredClaimsContain as $claim => $needle) {
            if (key_exists($claim, $claimsSet)){
                $value = $claimsSet[$claim];
                if(is_array($value)) {
                    if(!in_array($needle, $value))
                        throw new InvalidClaimException("Claim '$claim' (array) does not contain string '$needle'");
                } else
                if(strpos((string) $value, (string) $needle) === false) {
                    throw new InvalidClaimException("Claim '$claim':'$value (string) does not contain string '$needle'");
                }
            } else {
                throw new InvalidClaimException("Claim '$claim' missing");
            }
        }
    }

}
