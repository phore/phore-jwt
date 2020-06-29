<?php


use Phore\JWT\JWK\RsaPublicKey;
use PHPUnit\Framework\TestCase;

class RsaPublicKeyTest extends TestCase
{
    public function testRsaPublicKey()
    {
        $key = new RsaPublicKey('mod', 'exp');
        $jwkArray = $key->getArray();
        $this->assertEquals('RSA', $jwkArray['kty']);
        $this->assertEquals('mod', $jwkArray['n']);
        $this->assertEquals('exp', $jwkArray['e']);
    }

}
