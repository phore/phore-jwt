<?php


use Phore\JWT\Jwa;
use Phore\JWT\JWK\JwkFactory;
use Phore\JWT\JWK\Jwks;
use Phore\JWT\JwsDecoder;
use Phore\JWT\Jwt;
use Phore\JWT\JwtEncoder;
use PHPUnit\Framework\TestCase;

class Test extends TestCase
{
    public function testRsa()
    {
        $rsaPrivateKey = JwkFactory::loadPem(trim(file_get_contents(__DIR__ . "/../mockData/secrets/private-key-rsa2048.pem")));
        $rsaPrivateKey->setAlgorithm(Jwa::RS256);
//        print_r($rsaPrivateKey);
        $jwks = new Jwks();
        $kidPrivate = $jwks->addJwk($rsaPrivateKey);
        $encoder = new JwtEncoder();
        $encoder->setJwks($jwks);
        $claims = ['iss' => 'https://example.com', 'aud' => 'client', 'exp' => time()+100, 'iat' => time()-100, 'sub' => 'sub'];
        $jwt = new Jwt($claims);
        $jws = $encoder->encode($jwt, $kidPrivate);

        $decoder = new JwsDecoder();
        $rsaPublicKey = $rsaPrivateKey->getPublicKey();
        $jwks2 = new Jwks();
        $kidPublic = $jwks2->addJwk($rsaPublicKey);
        $decoder->setJwks($jwks2);
        $decoder->setIssuer('https://example.com');
        $decoder->setClientId('client');
        $jwtDecoded = $decoder->decode($jws);

        $this->assertEquals($kidPrivate, $kidPublic);
        $this->assertEquals($jwt, $jwtDecoded);

    }
}
