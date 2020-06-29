<?php


use Phore\JWT\JWK\SymmetricKey;
use PHPUnit\Framework\TestCase;

class SymmetricKeyTest extends TestCase
{
    public function testSymmetricKey()
    {
        $key = new SymmetricKey("supersecretSecret");
        $jwkArray = $key->getArray();
        $this->assertEquals('oct', $jwkArray['kty']);
        $this->assertEquals('supersecretSecret', $jwkArray['k']);
    }

}
