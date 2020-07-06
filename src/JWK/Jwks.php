<?php


namespace Phore\JWT\JWK;

class Jwks
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
            $this->keys[] = $key;
        }
    }

    public function addJwk(Jwk $jwk)
    {
        //TODO: When jwk has no kid create one (maybe using jkw signature?)
        //TODO: When jwk has a kid make sure it doesnt conflict with existing ones (same id is allowed for different types/algs?)
        $this->keys[] = $jwk;
    }

    public function getKey(string $kid) : ?Jwk
    {
        foreach ($this->keys as $jwk) {
            if($jwk->getKeyId() === $kid)
                return $jwk;
        }
        return null;
    }

}
