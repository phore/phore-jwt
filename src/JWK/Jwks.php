<?php


namespace Phore\JWT\JWK;

use JsonSerializable;

class Jwks implements JsonSerializable
{
    /**
     * @var Jwk[]
     */
    private $keys;

    /**
     * Jwks constructor.
     * @param JWK ...$jwk
     */
    public function __construct(JWK ...$jwk)
    {
        $this->keys = [];
        foreach ($jwk as $key) {
            $this->addJwk($key);
        }
    }

    /**
     * Add a Jwk to the key set. The KeyId will be the value set in the JWK or its thumbprint
     * @param Jwk $jwk
     * @return string KeyId
     */
    public function addJwk(Jwk $jwk) : string
    {
        //If JWK has no keyId use the thumbprint
        $kid = $jwk->getKeyId() ?? $jwk->getThumbprint();
        $jwk->setKeyId($kid);
        //TODO: When jwk has a kid make sure it doesnt conflict with existing ones (same id is allowed for different types/algs?)
        $this->keys[$kid] = $jwk;
        return $kid;
    }

    public function getKey(string $kid) : ?Jwk
    {
        return $this->keys[$kid] ?? null;
    }

    public function jsonSerialize()
    {
        $jwks['keys'] = [];

        foreach ($this->keys as $kid => $jwk) {
            $jwks['keys'] = [$jwk->getArray()];
        }

        return $jwks;
    }
}
