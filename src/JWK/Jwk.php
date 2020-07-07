<?php

declare(strict_types=1);

namespace Phore\JWT\JWK;


abstract class Jwk
{
    protected $keyType;
    protected $publicKeyUse; // use
    protected $keyOperations; // key_ops
    protected $algorithm; // alg
    protected $keyId; // kid

    private $pemEncodedString; // pem encoded representation of the key

    /**
     * Jwk constructor.
     * @param string $keyType kty - one of EC, RSA, oct
     */
    public function __construct(string $keyType)
    {
        $this->keyType = $keyType;
    }

    /**
     * @return string json-encoded
     */
    public function __toString(): string {
        $array = $this->getArray();
        return json_encode($array, JSON_PRESERVE_ZERO_FRACTION|JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
    }

    /**
     * @return array json assoc array
     */
    public function getArray() : array
    {
        return $this->getKeyMetaArray() + $this->getKeyComponentArray();
    }

    protected abstract function getKeyComponentArray() : array;

    protected function getKeyMetaArray() : array
    {
        $jwk['kty'] = $this->keyType;
        if(isset($this->publicKeyUse))
            $jwk['use'] = $this->publicKeyUse;
        if(isset($this->keyOperations))
            $jwk['key_ops'] = $this->keyOperations;
        if(isset($this->algorithm))
            $jwk['alg'] = $this->algorithm;
        if(isset($this->keyId))
            $jwk['kid'] = $this->keyId;
        return $jwk;
    }

    /**
     * Return the pem encoded string representation of the key
     * @return string
     */
    public abstract function getPem() : string;

    /**
     * Calculate the key thumbprint using SHA-256 as defined in rfc7638
     * @return string
     */
    public function getThumbprint() : string
    {
        $thumbprint = $this->getThumbprintArray();
        ksort($thumbprint);
        return base64urlEncode(hash('sha256', jsonEncode($thumbprint), true));
    }

    /**
     * Gather and lexicographically sort the required parts to calculate the thumbprint
     * @return array
     */
    protected abstract function getThumbprintArray() : array ;

    public function setKeyId(string $keyId)
    {
        $this->keyId = $keyId;
    }

    public function getKeyId()
    {
        return $this->keyId;
    }

    /**
     * @return mixed
     */
    public function getAlgorithm()
    {
        return $this->algorithm;
    }

    /**
     * @param mixed $algorithm
     */
    public function setAlgorithm($algorithm): void
    {
        $this->algorithm = $algorithm;
    }

    /**
     * @param mixed $pemEncodedString
     */
    public function setPemEncodedString($pemEncodedString): void
    {
        $this->pemEncodedString = $pemEncodedString;
    }

    /**
     * @return mixed
     */
    protected function getPemEncodedString()
    {
        return $this->pemEncodedString;
    }

}
