<?php


namespace Phore\JWT;

use Phore\JWT\Exceptions\InvalidAlgorithmException;
use Phore\JWT\Exceptions\InvalidClaimException;
use Phore\JWT\Exceptions\InvalidHeaderException;
use Phore\JWT\Exceptions\InvalidJwtFormatException;
use Phore\JWT\Exceptions\InvalidSignatureException;
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
     * @var array ClientIds that must present int the 'aud' claim (in addition to the clientIc specified above)
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
    private $jwks;

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
        $this->additionalHeaders = [];
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

    /**
     * @param Jwks $jwks
     */
    public function setJwks(Jwks $jwks): void
    {
        $this->jwks = $jwks;
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
        $this->validateSignature($header->alg, $header->kid, $jwsComponents[0].$jwsComponents[1]);
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

    private function validateSignature(string $tokenAlg, string $tokenKid, string $b64headerPayload) {
        $jwk = $this->jwks->getKey($tokenKid);
        switch ($tokenAlg) {
            case Jwa::RS256:
                $rsaSignatureAlg = OPENSSL_ALGO_SHA256;
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
        if(!$claimsSet['iss'] == $this->issuer) {
            throw new InvalidClaimException("Invalid token issuer");
        }
        if(is_array($claimsSet['aud'])) {
            if(!in_array($this->clientId, $claimsSet['aud'])) {
                throw new InvalidClaimException("Client not listed as audience");
            }
        } else if($this->clientId != $claimsSet['aud']) {
            throw new InvalidClaimException("Client not listed as audience");
        }

        if($claimsSet['exp'] < time()) {
            throw new InvalidClaimException("Token expired");
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
