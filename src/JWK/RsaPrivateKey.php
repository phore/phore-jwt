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
        $jwk['n'] = $this->modulus;
        $jwk['e'] = $this->exponent;
        $jwk['d'] = $this->privateExponent;
        $jwk['p'] = $this->firstPrimeFactor;
        $jwk['q'] = $this->secondPrimeFactor;
        $jwk['dp'] = $this->firstFactorCrtExponent;
        $jwk['dq'] = $this->secondFactorCrtExponent;
        $jwk['qi'] = $this->firstCrtCoefficient;

        return $jwk;
    }
}
