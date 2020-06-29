<?php


use Phore\JWT\JWK\RsaPrivateKey;
use PHPUnit\Framework\TestCase;

class RsaPrivateKeyTest extends TestCase
{
    public function testRsaPrivateKey()
    {
        $key = new RsaPrivateKey(
            'n',
            'e',
            'd',
            'p',
            'q',
            'dp',
            'dq',
            'qi'
        );
        $jwkArray = $key->getArray();
        $this->assertEquals('RSA', $jwkArray['kty']);
        $this->assertEquals('n', $jwkArray['n']);
        $this->assertEquals('e', $jwkArray['e']);
        $this->assertEquals('d', $jwkArray['d']);
        $this->assertEquals('p', $jwkArray['p']);
        $this->assertEquals('q', $jwkArray['q']);
        $this->assertEquals('dp', $jwkArray['dp']);
        $this->assertEquals('dq', $jwkArray['dq']);
        $this->assertEquals('qi', $jwkArray['qi']);
    }
}
