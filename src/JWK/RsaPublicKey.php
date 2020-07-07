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
        return $jwk;
    }

    protected function getThumbprintArray(): array
    {
        $thumbprint = $this->getKeyComponentArray();
        $thumbprint['kty'] = $this->keyType;
        return $thumbprint;
    }
}
