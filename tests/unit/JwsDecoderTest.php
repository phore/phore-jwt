<?php

namespace Phore\Tests;

use Phore\JWT\Exceptions\InvalidClaimException;
use Phore\JWT\Jwa;
use Phore\JWT\JWK\JwkFactory;
use Phore\JWT\JWK\Jwks;
use Phore\JWT\JwsDecoder;
use Phore\JWT\Jwt;
use Phore\JWT\JwtEncoder;
use PHPUnit\Framework\TestCase;

class JwsDecoderTest extends TestCase
{
    public $decoder;
    public $encoder;
    public $jwksPublic;
    public $jwksPrivate;
    public $privateKeyId;

    protected function setUp(): void
    {
        $keyString = trim(file_get_contents(__DIR__ . "/../mockData/secrets/private-key-rsa2048.pem"));
        $jwk = JwkFactory::loadPem($keyString);
        $jwk->setAlgorithm(Jwa::RS256);
        $this->jwksPrivate = new Jwks();
        $this->privateKeyId = $this->jwksPrivate->addJwk($jwk);

        $this->encoder = new JwtEncoder($this->jwksPrivate);

        $keyString = trim(file_get_contents(__DIR__ . "/../mockData/secrets/public-key-rsa2048.pem"));
        $jwk = JwkFactory::loadPem($keyString);
        $this->jwksPublic = new Jwks($jwk);

        $this->decoder = new JwsDecoder();
        $this->decoder = new JwsDecoder();
        $this->decoder->setIssuer("https://example.com");
        $this->decoder->setClientId("client");
        $this->decoder->setJwks($this->jwksPublic);
    }

    public function testDecodeRs256Token()
    {

        $this->decoder->setRequiredClaims(['test']);
        $this->decoder->setRequiredClaimsContain(['test' => 12]);

        $tokenString = trim(file_get_contents(__DIR__ . "/../mockData/rs256-JWS.jwt"));
        $jwt = $this->decoder->decode($tokenString);

        $this->assertEquals(123, $jwt->getClaim('test'));
    }

    public function testValidationFailsWhenSubIsMissing()
    {
        $claims = ['iss' => 'https://example.com', 'aud' => 'client', 'exp' => time()+10, 'iat' => 120];
        $jwt = new Jwt($claims);
        $tokenString = $this->encoder->encode($jwt, $this->privateKeyId);
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage("Claim 'sub' missing");
        $this->decoder->decode($tokenString);
    }

    public function testValidationFailsWhenIssuerInvalid()
    {
        $claims = ['iss' => 'failure', 'aud' => 'client', 'exp' => time()+10, 'iat' => 120, 'sub' => 'sub'];
        $jwt = new Jwt($claims);
        $tokenString = $this->encoder->encode($jwt, $this->privateKeyId);
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage("Invalid token issuer");
        $this->decoder->decode($tokenString);
    }

    public function testValidationFailsWhenClientNotInAudienceArray()
    {
        $claims = ['iss' => 'https://example.com', 'aud' => ['abc'], 'exp' => 123, 'iat' => 120, 'sub' => 'sub'];
        $jwt = new Jwt($claims);
        $tokenString = $this->encoder->encode($jwt, $this->privateKeyId);
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage("Client 'client' not listed as audience");
        $this->decoder->decode($tokenString);
    }

    public function testValidationFailsWhenClientDoesNotEqualAudienceString()
    {
        $claims = ['iss' => 'https://example.com', 'aud' => 'abc', 'exp' => 123, 'iat' => 120, 'sub' => 'sub'];
        $jwt = new Jwt($claims);
        $tokenString = $this->encoder->encode($jwt, $this->privateKeyId);
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage("Client 'client' not listed as audience");
        $this->decoder->decode($tokenString);
    }

    public function testValidationFailsWhenTokenIsExpired()
    {
        $claims = ['iss' => 'https://example.com', 'aud' => 'client', 'exp' => time()-10, 'iat' => time()-100, 'sub' => 'sub'];
        $jwt = new Jwt($claims);
        $tokenString = $this->encoder->encode($jwt, $this->privateKeyId);
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage("Token expired");
        $this->decoder->decode($tokenString);
    }

    public function testValidationFailsWhenTokenIsIssuedInTheFuture()
    {
        $claims = ['iss' => 'https://example.com', 'aud' => 'client', 'exp' => time()+10, 'iat' => time()+100, 'sub' => 'sub'];
        $jwt = new Jwt($claims);
        $tokenString = $this->encoder->encode($jwt, $this->privateKeyId);
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage("Token looks suspiciously futuristic");
        $this->decoder->decode($tokenString);
    }

    public function testValidationFailsWhenRequiredClaimsMissing()
    {
        $claims = ['iss' => 'https://example.com', 'aud' => 'client', 'exp' => time()+10, 'iat' => 100, 'sub' => 'sub'];
        $jwt = new Jwt($claims);
        $tokenString = $this->encoder->encode($jwt, $this->privateKeyId);
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage("Claim 'fail' missing");
        $this->decoder->setRequiredClaims(['fail']);
        $this->decoder->decode($tokenString);
    }

    public function testValidationFailsWhenRequiredClaimDoesNotContainString()
    {
        $claims = ['iss' => 'https://example.com', 'aud' => 'client', 'exp' => time()+10, 'iat' => 100, 'sub' => 'sub'];
        $jwt = new Jwt($claims);
        $jwt->setClaim('roles', ['dev']);
        $tokenString = $this->encoder->encode($jwt, $this->privateKeyId);
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage("Claim 'roles' (array) does not contain string 'admin'");
        $this->decoder->setRequiredClaimsContain(['roles' => 'admin']);
        $this->decoder->decode($tokenString);
    }

}
