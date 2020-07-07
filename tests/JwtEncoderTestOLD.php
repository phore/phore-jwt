<?php

namespace Phore\Tests;

use Phore\JWT\Jwt;
use Phore\JWT\JwtEncoder;
use PHPUnit\Framework\TestCase;

class JwtEncoderTestOLD extends TestCase
{
    public function testEncodeJwsAlgNone()
    {
        $token = new Jwt();
        $token->setClaim("key", "val");
        $encoder = new JwtEncoder();
        $encoder->setSecret("none", "");
        $jws = $encoder->encode($token);
        $this->assertEquals(trim(file_get_contents(__DIR__ . "/mockData/unsecuredJWS.jwt")), $jws);
    }

    public function testEncodeJwsAlgHS256()
    {
        $token = new Jwt();
        $token->setClaim("key", "val");
        $encoder = new JwtEncoder();
        $encoder->setSecret("HS256", "abc123");
        $jws = $encoder->encode($token);
        $this->assertEquals(trim(file_get_contents(__DIR__ . "/mockData/hs256-JWS.jwt")), $jws);
    }

    public function testEncodeJwsAlgHS512()
    {
        $token = new Jwt();
        $token->setClaim("key", "val");
        $encoder = new JwtEncoder();
        $encoder->setSecret("HS512", "abc123");
        $jws = $encoder->encode($token);
        $this->assertEquals(trim(file_get_contents(__DIR__ . "/mockData/hs512-JWS.jwt")), $jws);
    }

    public function testEncodeJwsAlgRS256ThrowsExceptionOnInvalidKey()
    {
        $token = new Jwt();
        $token->setClaim("key", "val");
        $encoder = new JwtEncoder();
        $encoder->setSecret("RS256", "abc123");
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage("Secret must be a valid PEM-formatted RSA Private Key");
        @$encoder->encode($token); //the @ suppresses the openssl_sign warning being converted to an exception by phpunit
    }

    public function testEncodeJwsAlgRS256()
    {
        $token = new Jwt();
        $token->setClaim("key", "val");
        $encoder = new JwtEncoder();
        $encoder->setSecret("RS256", trim(file_get_contents(__DIR__ . "/mockData/secrets/private-key-rsa4096.pem")));
        $jws = $encoder->encode($token);
        $this->assertEquals(trim(file_get_contents(__DIR__ . "/mockData/rs256-JWS.jwt")), $jws);
    }

    public function testEncodeJwsAlgRS512()
    {
        $token = new Jwt();
        $token->setClaim("key", "val");
        $encoder = new JwtEncoder();
        $encoder->setSecret("RS512", trim(file_get_contents(__DIR__ . "/mockData/secrets/private-key-rsa4096.pem")));
        $jws = $encoder->encode($token);
        $this->assertEquals(trim(file_get_contents(__DIR__ . "/mockData/rs512-JWS.jwt")), $jws);
    }
}
