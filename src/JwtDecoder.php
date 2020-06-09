<?php


namespace Phore\JWT;


class JwtDecoder
{


    /**
     * @var callable|null
     */
    private $publicKeyLoader = null;


    public function setPublicKeyLoader(callable $cb)
    {
        $this->publicKeyLoader = $cb;
    }



    public function decode(string $tokenData)
    {

        $unverifiedToken = $this->_decodeStrToken($tokenData);


        if ($this->publicKeyLoader !== null) {
            $this->addPublicKey(($this->publicKeyLoader)($unverifiedToken));
        }


        $verifiedToken = $this->_verifyConstraints($unverifiedToken);

        return $verifiedToken;



    }


}
