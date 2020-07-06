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
        $jwk = $this->getBasicArray();
        $jwk['k'] = $this->keyValue;

        return $jwk;
    }

    public function getPem(): string
    {
        // TODO: Implement getPem() method.
        return "";
    }
}
