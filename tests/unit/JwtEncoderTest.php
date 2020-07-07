<?php

namespace Phore\Tests;

use Phore\JWT\Jwa;
use Phore\JWT\JWK\JwkFactory;
use Phore\JWT\JWK\Jwks;
use Phore\JWT\Jwt;
use Phore\JWT\JwtEncoder;
use PHPUnit\Framework\TestCase;

class JwtEncoderTest extends TestCase
{
    public function testEncodeJwsWithRsa()
    {
        // Prepare JwtEncoder
        $keyString = trim(file_get_contents(__DIR__ . "/../mockData/secrets/private-key-rsa2048.pem"));
        $jwk = JwkFactory::loadPem($keyString);
        $jwk->setAlgorithm(Jwa::RS256);
        $jwkSet = new Jwks();
        $kid = $jwkSet->addJwk($jwk);
        $encoder = new JwtEncoder($jwkSet);

        $claimsSet = [
            'iss' => 'https://example.com',
            'sub' => 'user',
            'aud' => 'client',
            'azp' => 'client',
            'exp' => 253373920500,
            'iat' => 1594154023,
            'test' => 123
        ];

        // Generate and Encode JWT
        $jwt = new Jwt($claimsSet);
        $token = $encoder->encode($jwt, $kid);

        // assert
        $expectedToken = trim(file_get_contents(__DIR__ . "/../mockData/rs256-JWS.jwt"));
        $this->assertEquals($expectedToken, $token);
    }

}
