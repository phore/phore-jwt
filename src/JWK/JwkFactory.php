<?php


namespace Phore\JWT\JWK;


class JwkFactory
{
    public function loadJwkString(string $json) : Jwk
    {
        //TODO: create a jwk from a jwk json string
        throw new \InvalidArgumentException("Invalid or unsupported JWK format.");
    }

    public function loadPem(string $pem) : Jwk
    {
        //TODO: create jwk from pem encoded pkcs
        throw new \InvalidArgumentException("Invalid or unsupported PEM format.");
    }

    public function createJwk(string $alg) : Jwk
    {
        //TODO: create a new jwk with supplied algorithm
        throw new \InvalidArgumentException("Invalid or unsupported algorithm.");
    }

}
