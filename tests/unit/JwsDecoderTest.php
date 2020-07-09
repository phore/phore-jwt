<?php

namespace Phore\Tests;

use Phore\JWT\JWK\JwkFactory;
use Phore\JWT\JWK\Jwks;
use Phore\JWT\JwsDecoder;
use PHPUnit\Framework\TestCase;

class JwsDecoderTest extends TestCase
{
    public function testDecodeRs256Token()
    {
        $keyString = trim(file_get_contents(__DIR__ . "/../mockData/secrets/public-key-rsa2048.pem"));
        $jwk = JwkFactory::loadPem($keyString);
        $jwks = new Jwks($jwk);

        $decoder = new JwsDecoder();
        $decoder->setIssuer("issuer");
        $decoder->setClientId("client");
        $decoder->setJwks($jwks);
        $decoder->setRequiredClaims(['test']);
        $decoder->setRequiredClaimsContain(['test' => 12]);

        $tokenString = trim(file_get_contents(__DIR__ . "/../mockData/rs256-JWS.jwt"));
        $jwt = $decoder->decode($tokenString);

        $this->assertEquals(123, $jwt->getClaim('test'));
    }

}
