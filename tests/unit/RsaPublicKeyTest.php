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
        $this->assertEquals(base64_encode('mod'), $jwkArray['n']);
        $this->assertEquals(base64_encode('exp'), $jwkArray['e']);
    }

}
