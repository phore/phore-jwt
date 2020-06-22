<?php


use Phore\ASN\KeyFactory;
use Phore\JWT\JsonWebAlgorithms;
use Phore\JWT\JwtDecoder;
use PHPUnit\Framework\TestCase;

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
        $decoder->setSingleSecret(JsonWebAlgorithms::HS256, 'abc123');
        $jwt = $decoder->decode($token);
        $this->assertEquals('does not exist', $jwt->getClaim('claim123', 'does not exist'));
        $this->assertEquals('val', $jwt->getClaim('key', 'does not exist'));
        $this->assertEquals(JsonWebAlgorithms::HS256, $jwt->getHeader('alg'));
    }

    public function testDecodeJwsHS512()
    {
        $token = trim(file_get_contents(__DIR__ . "/mockData/hs512-JWS.jwt"));
        $decoder = new JwtDecoder();
        $decoder->setSingleSecret(JsonWebAlgorithms::HS512, 'abc123');
        $jwt = $decoder->decode($token);
        $this->assertEquals('does not exist', $jwt->getClaim('claim123', 'does not exist'));
        $this->assertEquals('val', $jwt->getClaim('key', 'does not exist'));
        $this->assertEquals(JsonWebAlgorithms::HS512, $jwt->getHeader('alg'));
    }

    public function testDecodeJwsRS256()
    {
        $token = trim(file_get_contents(__DIR__ . "/mockData/rs256-JWS.jwt"));
        $decoder = new JwtDecoder();
        $secret = KeyFactory::loadKey(trim(file_get_contents(__DIR__ . "/mockData/secrets/public-key-rsa4096.pem")));
        $decoder->setSingleSecret(JsonWebAlgorithms::RS256, $secret->exportPem());
        $jwt = $decoder->decode($token);
        $this->assertEquals('does not exist', $jwt->getClaim('claim123', 'does not exist'));
        $this->assertEquals('val', $jwt->getClaim('key', 'does not exist'));
        $this->assertEquals(JsonWebAlgorithms::RS256, $jwt->getHeader('alg'));
    }

    public function testDecodeJwsRS512()
    {
        $token = trim(file_get_contents(__DIR__ . "/mockData/rs512-JWS.jwt"));
        $decoder = new JwtDecoder();
        $secret = KeyFactory::loadKey(trim(file_get_contents(__DIR__ . "/mockData/secrets/public-key-rsa4096.pem")));
        $decoder->setSingleSecret(JsonWebAlgorithms::RS512, $secret->exportPem());
        $jwt = $decoder->decode($token);
        $this->assertEquals('does not exist', $jwt->getClaim('claim123', 'does not exist'));
        $this->assertEquals('val', $jwt->getClaim('key', 'does not exist'));
        $this->assertEquals(JsonWebAlgorithms::RS512, $jwt->getHeader('alg'));
    }



}
