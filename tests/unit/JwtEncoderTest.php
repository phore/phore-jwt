<?php


use Phore\JWT\Jwa;
use Phore\JWT\JWK\JwkFactory;
use Phore\JWT\JWK\Jwks;
use Phore\JWT\JwtEncoder;
use PHPUnit\Framework\TestCase;

class JwtEncoderTest extends TestCase
{
    public function testEncodeJwsWithRsa()
    {
        $keyString = trim(file_get_contents(__DIR__ . "/../mockData/secrets/private-key-rsa4096.pem"));
        $jwk = JwkFactory::loadPem($keyString);
        $jwk->setKeyId("abc");
        $jwk->setAlgorithm(Jwa::RS256);
        $jwks = new Jwks($jwk);
        $encoder = new JwtEncoder($jwks);

        $jwt = new Phore\JWT\Jwt(['test' => 123]);
        $token = $encoder->encode($jwt, 'abc');
        print_r($token);
        $expectedToken = trim(file_get_contents(__DIR__ . "/../mockData/rs256-JWS.jwt"));
        $this->assertEquals($expectedToken, $token);

    }

}
