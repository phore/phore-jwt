<?php


use Phore\JWT\JwtDecoder;
use PHPUnit\Framework\TestCase;

class JwtDecoderTest extends TestCase
{
    public function testDecodeFailsOnInvalidJwt()
    {
        $token = "failToken";
        $decoder = new JwtDecoder();
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage("Token '" . substr($token, 0, 9) . "...' is not a valid JWT.");
        $decoder->decode($token);
    }

}
