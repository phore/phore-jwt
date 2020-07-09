<?php

namespace Phore\Tests;

use Exception;
use InvalidArgumentException;
use Phore\JWT\Jwa;
use Phore\JWT\JWK\JwkFactory;
use Phore\JWT\JwtDecoder;
use PHPUnit\Framework\TestCase;
use UnexpectedValueException;

class JwtDecoderTest extends TestCase
{
    public function testDecoderFailsIfNoSecretAndAlgWereSpecified()
    {
        $decoder = new JwtDecoder();
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage("Cannot decode token: No key available.");
        $decoder->decode("test");
    }

    public function testDecodeFailsOnInvalidJwt()
    {
        $token = "failToken";
        $decoder = new JwtDecoder();
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage("Token '" . substr($token, 0, 9) . "...' is not a valid JWT.");
        $decoder->setSingleSecret('none', '');
        $decoder->decode($token);
    }

    public function testDecodeUnsecuredJwsDenied()
    {
        $token = trim(file_get_contents(__DIR__ . "/mockData/unsecuredJWS.jwt"));
        $decoder = new JwtDecoder();
        $this->expectException(Exception::class);
        $this->expectExceptionMessage("Unsecured JWS is not allowed.");
        $decoder->setSingleSecret('none', '');
        $decoder->decode($token);
    }

    public function testDecodeUnsecuredJws()
    {
        $token = trim(file_get_contents(__DIR__ . "/mockData/unsecuredJWS.jwt"));
        $decoder = new JwtDecoder();
        $decoder->setAllowUnsecuredJws(true);
        $decoder->setSingleSecret('none', '');
        $jwt = $decoder->decode($token);
        $this->assertEquals('does not exist', $jwt->getClaim('claim123', 'does not exist'));
        $this->assertEquals('none', $jwt->getHeader('alg'));
    }

    public function testDecodeJwsThrowsExceptionWhenDefinedJWADoesNotMatchTokenAlg()
    {
        $token = trim(file_get_contents(__DIR__ . "/mockData/rs256-JWS.jwt"));
        $decoder = new JwtDecoder();
        $this->expectException(Exception::class);
        $this->expectExceptionMessage("Algorithm 'RS256' is not supported");
        $decoder->setSingleSecret('HS256', 'fail');
        $jwt = $decoder->decode($token);
    }

    public function testDecodeJwsThrowsExceptionWhenDefinedSecretDoesNotMatch()
    {
        $token = trim(file_get_contents(__DIR__ . "/mockData/hs256-JWS.jwt"));
        $decoder = new JwtDecoder();
        $this->expectException(Exception::class);
        $this->expectExceptionMessage("Invalid Signature");
        $decoder->setSingleSecret('HS256', 'fail');
        $decoder->decode($token);
    }

    public function testDecodeJwsHS256()
    {
        $token = trim(file_get_contents(__DIR__ . "/mockData/hs256-JWS.jwt"));
        $decoder = new JwtDecoder();
        $decoder->setSingleSecret(Jwa::HS256, 'abc123');
        $jwt = $decoder->decode($token);
        $this->assertEquals('does not exist', $jwt->getClaim('claim123', 'does not exist'));
        $this->assertEquals('val', $jwt->getClaim('key', 'does not exist'));
        $this->assertEquals(Jwa::HS256, $jwt->getHeader('alg'));
    }

    public function testDecodeJwsHS512()
    {
        $token = trim(file_get_contents(__DIR__ . "/mockData/hs512-JWS.jwt"));
        $decoder = new JwtDecoder();
        $decoder->setSingleSecret(Jwa::HS512, 'abc123');
        $jwt = $decoder->decode($token);
        $this->assertEquals('does not exist', $jwt->getClaim('claim123', 'does not exist'));
        $this->assertEquals('val', $jwt->getClaim('key', 'does not exist'));
        $this->assertEquals(Jwa::HS512, $jwt->getHeader('alg'));
    }

    public function testDecodeJwsRS256()
    {
        $token = trim(file_get_contents(__DIR__ . "/mockData/rs256-JWS.jwt"));
        $decoder = new JwtDecoder();
        $key = JwkFactory::loadPem(trim(file_get_contents(__DIR__ . "/mockData/secrets/public-key-rsa2048.pem")));
        $decoder->setSingleSecret(Jwa::RS256, $key->getPem());
        $jwt = $decoder->decode($token);
        $this->assertEquals('does not exist', $jwt->getClaim('claim123', 'does not exist'));
        $this->assertEquals(123, $jwt->getClaim('test', 'does not exist'));
        $this->assertEquals(Jwa::RS256, $jwt->getHeader('alg'));
    }

    public function testDecodeJwsRS512()
    {
        $token = trim(file_get_contents(__DIR__ . "/mockData/rs512-JWS.jwt"));
        $decoder = new JwtDecoder();
        $key = JwkFactory::loadPem(trim(file_get_contents(__DIR__ . "/mockData/secrets/public-key-rsa4096.pem")));
        $decoder->setSingleSecret(Jwa::RS512, $key->getPem());
        $jwt = $decoder->decode($token);
        $this->assertEquals('does not exist', $jwt->getClaim('claim123', 'does not exist'));
        $this->assertEquals('val', $jwt->getClaim('key', 'does not exist'));
        $this->assertEquals(Jwa::RS512, $jwt->getHeader('alg'));
    }



}
