<?php


namespace Phore\JWT;

use Phore\JWT\JWK\Jwk;

class Jwks
{
    private $keys = [];

    public function addJwk(Jwk $jwk)
    {
        //TODO: When jwk has no kid create one (maybe using jkw signature?)
        //TODO: When jwk has a kid make sure it doesnt conflict with existing ones (same id is allowed for different types/algs?)
        $this->keys[] = $jwk;
    }

}
