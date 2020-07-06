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
        $jwk['n'] = base64_encode($this->modulus);
        $jwk['e'] = base64_encode($this->exponent);

        return $jwk;
    }

    public function getPem(): string
    {
        // TODO: Implement getPem() method.
        return "";
    }
}
