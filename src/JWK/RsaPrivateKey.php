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

    public function getArray(): array
    {
        $jwk = $this->getBasicArray();
        $jwk['n'] = base64_encode($this->modulus);
        $jwk['e'] = base64_encode($this->exponent);
        $jwk['d'] = base64_encode($this->privateExponent);
        $jwk['p'] = base64_encode($this->firstPrimeFactor);
        $jwk['q'] = base64_encode($this->secondPrimeFactor);
        $jwk['dp'] = base64_encode($this->firstFactorCrtExponent);
        $jwk['dq'] = base64_encode($this->secondFactorCrtExponent);
        $jwk['qi'] = base64_encode($this->firstCrtCoefficient);

        return $jwk;
    }

    public function getPem(): string
    {
        return "";

    }
}
