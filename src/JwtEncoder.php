<?php


namespace Phore\JWT;


class JwtEncoder
{

    public function encode(JwtToken $jwt) : string
    {
        // return jwt

    }

    /**
     * Set the algorithm to sign the token
     * @param string $alg
     * @return $this
     */
    public function setAlg(string $alg) : self
    {
        return $this;
    }

    private function sign() : string
    {
        // return jws
    }


}
