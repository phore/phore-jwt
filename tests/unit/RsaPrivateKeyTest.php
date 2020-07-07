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
        $this->assertEquals(base64urlEncode('n'), $jwkArray['n']);
        $this->assertEquals(base64urlEncode('e'), $jwkArray['e']);
        $this->assertEquals(base64urlEncode('d'), $jwkArray['d']);
        $this->assertEquals(base64urlEncode('p'), $jwkArray['p']);
        $this->assertEquals(base64urlEncode('q'), $jwkArray['q']);
        $this->assertEquals(base64urlEncode('dp'), $jwkArray['dp']);
        $this->assertEquals(base64urlEncode('dq'), $jwkArray['dq']);
        $this->assertEquals(base64urlEncode('qi'), $jwkArray['qi']);
    }

    public function testThumbprint()
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
        $thumbprint = $key->getThumbprint();

        $this->assertEquals('QXDVYlIDF6DxyTivEovW7lQ9D0h0JgFfcyl3KyZBtDo', $thumbprint);

    }
}
