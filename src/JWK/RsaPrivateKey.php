<?php


namespace Phore\JWT\JWK;

class RsaPrivateKey extends Jwk
{
    private $modulus;
    private $exponent;
    private $privateExponent;
    private $firstPrimeFactor;
    private $secondPrimeFactor;
    private $firstFactorCrtExponent;
    private $secondFactorCrtExponent;
    private $firstCrtCoefficient;

    /**
     * RsaPrivateKey constructor.
     * @param string $modulus n - binary string
     * @param string $exponent e - binary string
     * @param string $privateExponent d - binary string
     * @param string $firstPrimeFactor p - binary string
     * @param string $secondPrimeFactor q - binary string
     * @param string $firstFactorCrtExponent dp - binary string
     * @param string $secondFactorCrtExponent dq - binary string
     * @param string $firstCrtCoefficient qi - binary string
     */
    public function __construct(
        string $modulus,
        string $exponent,
        string $privateExponent,
        string $firstPrimeFactor,
        string $secondPrimeFactor,
        string $firstFactorCrtExponent,
        string $secondFactorCrtExponent,
        string $firstCrtCoefficient
    ) {
        $keyType = 'RSA';
        parent::__construct($keyType);
        $this->modulus = $modulus;
        $this->exponent = $exponent;
        $this->privateExponent = $privateExponent;
        $this->firstPrimeFactor = $firstPrimeFactor;
        $this->secondPrimeFactor = $secondPrimeFactor;
        $this->firstFactorCrtExponent = $firstFactorCrtExponent;
        $this->secondFactorCrtExponent = $secondFactorCrtExponent;
        $this->firstCrtCoefficient = $firstCrtCoefficient;
    }

    public function getPem(): string
    {
        return $this->getPemEncodedString() ?? $this->pemEncodeKey();

    }

    private function pemEncodeKey() : string
    {
        return "";
    }

    protected function getKeyComponentArray(): array
    {
        $jwk['n'] = base64urlEncode($this->modulus);
        $jwk['e'] = base64urlEncode($this->exponent);
        $jwk['d'] = base64urlEncode($this->privateExponent);
        $jwk['p'] = base64urlEncode($this->firstPrimeFactor);
        $jwk['q'] = base64urlEncode($this->secondPrimeFactor);
        $jwk['dp'] = base64urlEncode($this->firstFactorCrtExponent);
        $jwk['dq'] = base64urlEncode($this->secondFactorCrtExponent);
        $jwk['qi'] = base64urlEncode($this->firstCrtCoefficient);

        return $jwk;
    }

    protected function getThumbprintArray(): array
    {
        $thumbprint['e'] = base64urlEncode($this->exponent);
        $thumbprint['kty'] = $this->keyType;
        $thumbprint['n'] = base64urlEncode($this->modulus);
        return $thumbprint;
    }
}
