<?php


namespace Phore\JWT\JWK;


class SymmetricKey extends Jwk
{
    private $keyValue;

    /**
     * SymmetricKey constructor.
     * @param string $keyValue the key value
     */
    public function __construct(string $keyValue)
    {
        $keyType = 'oct';
        parent::__construct($keyType);
        $this->keyValue = $keyValue;
    }

    public function getArray(): array
    {
        $jwk = $this->getKeyMetaArray();
        $jwk['k'] = $this->keyValue;

        return $jwk;
    }

    public function getPem(): string
    {
        // TODO: Implement getPem() method, if there is any.. https://www.ietf.org/rfc/rfc1423.txt might help
        return "";
    }

    protected function getKeyComponentArray(): array
    {
        return ['k' => base64urlEncode($this->keyValue)];
    }

    protected function getThumbprintArray(): array
    {
        $thumbprint['k'] = base64urlEncode($this->keyValue);
        $thumbprint['kty'] = $this->keyType;

        return $thumbprint;
    }
}
