<?php


use Phore\JWT\JWK\JwkFactory;
use PHPUnit\Framework\TestCase;

class JwkFactoryTest extends TestCase
{
    public function testFactoryThrowsExceptionOnInvalidPemKey()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage("Invalid or unsupported PEM key format.");
        JwkFactory::loadPem("-----BEGIN PRIVATE KEY-----\nabc");
    }

    public function testLoadPemPrivateRsaKey()
    {
        $jwk = JwkFactory::loadPem(trim(file_get_contents(__DIR__ . "/../mockData/secrets/private-key-rsa4096.pem")));
        $expected = trim(file_get_contents(__DIR__ . "/../mockData/secrets/private-key-rsa4096.jwk"));
        $expected = preg_replace('/\s+/', '', $expected);
        $this->assertEquals($expected, (string) $jwk);
    }

    public function testLoadJwkPrivateRsaKey()
    {
//        $keyString = trim(file_get_contents(__DIR__ . "/../mockData/secrets/private-key-rsa4096.jwk"));
//        $jwk = JwkFactory::loadJwk($keyString);
//        $expected = preg_replace('/\s+/', '', $keyString);
//        $this->assertEquals($expected, (string) $jwk);
    }

}
