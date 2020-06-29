<?php


namespace Phore\JWT\JWK;


class RsaPublicKey extends Jwk
{
    private $modulus;
    private $exponent;

    /**
     * RsaPublicKey constructor.
     * @param string $modulus n - binary string
     * @param string $exponent e - binary string
     */
    public function __construct(string $modulus, string $exponent)
    {
        $keyType = 'RSA';
        parent::__construct($keyType);
        $this->modulus = $modulus;
        $this->exponent = $exponent;
    }

    public function getArray(): array
    {
        $jwk = $this->getBasicArray();
        $jwk['n'] = $this->modulus;
        $jwk['e'] = $this->exponent;

        return $jwk;
    }
}
