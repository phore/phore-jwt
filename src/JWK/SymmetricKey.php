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
        // TODO: Implement getPem() method.
        return "";
    }

    protected function getKeyComponentArray(): array
    {
        // TODO: Implement getKeyComponentArray() method.
    }

    protected function getThumbprintArray(): array
    {
        // TODO: Implement getThumbprintArray() method.
    }
}
