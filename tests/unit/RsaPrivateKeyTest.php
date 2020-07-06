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
        $this->assertEquals(base64_encode('n'), $jwkArray['n']);
        $this->assertEquals(base64_encode('e'), $jwkArray['e']);
        $this->assertEquals(base64_encode('d'), $jwkArray['d']);
        $this->assertEquals(base64_encode('p'), $jwkArray['p']);
        $this->assertEquals(base64_encode('q'), $jwkArray['q']);
        $this->assertEquals(base64_encode('dp'), $jwkArray['dp']);
        $this->assertEquals(base64_encode('dq'), $jwkArray['dq']);
        $this->assertEquals(base64_encode('qi'), $jwkArray['qi']);
    }
}
