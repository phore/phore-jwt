<?php


use Phore\JWT\Jwa;
use Phore\JWT\JWK\JwkFactory;
use Phore\JWT\JWK\Jwks;
use Phore\JWT\JWK\SymmetricKey;
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

    public function testHs256()
    {

        $symmetricKey = new SymmetricKey("clientSecret");

        $symmetricKey->setAlgorithm(Jwa::HS256);
        $jwks = new Jwks();
        $kid = $jwks->addJwk($symmetricKey);
        $encoder = new JwtEncoder();
        $encoder->setJwks($jwks);
        $claims = ['iss' => 'https://example.com', 'aud' => 'client', 'exp' => time()+100, 'iat' => time()-100, 'sub' => 'sub'];
        $jwt = new Jwt($claims);
        $jws = $encoder->encode($jwt, $kid);

//        $jws="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwic3ViIjoiMTIzNDU2Nzg5MCIsIm5hbWUiOiJKb2huIERvZSIsImlhdCI6MTUxNjIzOTAyMiwiYXVkIjoiY2xpZW50IiwiZXhwIjoxNzE3MjM5MDIyfQ.cJ60iiBTqc1nxaHZW23OhK9C18OwMn0-wMoTsr1JJ_A";

        $decoder = new JwsDecoder();
        $kid = $decoder->addJwk($symmetricKey);
        $decoder->setClientSecretKeyId($kid);
        $decoder->setIssuer('https://example.com');
        $decoder->setClientId('client');
        $jwtDecoded = $decoder->decode($jws);
        $this->assertNotEmpty($jwtDecoded);
    }
}
