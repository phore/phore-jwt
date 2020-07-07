<?php

namespace Phore\Tests;

use Phore\JWT\Exceptions\InvalidAlgorithmException;
use Phore\JWT\Exceptions\InvalidHeaderException;
use Phore\JWT\Exceptions\InvalidJwtFormatException;
use Phore\JWT\JwsDecoder;
use PHPUnit\Framework\TestCase;

class JwsDecoderTestOLD extends TestCase
{
    public function testTokenContainsMoreThanThreeParts()
    {
        $decoder = new JwsDecoder();
        $this->expectException(InvalidJwtFormatException::class);
        $this->expectExceptionMessage("JWS needs exactly three base64url-encoded components delimited by two period characters.");
        $decoder->decode("a.b.c.d.e");
    }

    public function testTokenContainsInvalidBase64urlCharacters()
    {
        $decoder = new JwsDecoder();
        $this->expectException(InvalidJwtFormatException::class);
        $this->expectExceptionMessage("JWS needs exactly three base64url-encoded components delimited by two period characters.");
        $decoder->decode("a+b.c&d.e?f");
    }

    public function testTokenContainsInvalidBase64urlEncodedJson()
    {
        $decoder = new JwsDecoder();
        $this->expectException(InvalidJwtFormatException::class);
        $this->expectExceptionMessage("JWS contains invalid Json.");
        $decoder->decode("abcd.efgh.ijkl");
    }

    public function testTokenHeaderAndPayloadMustBeJsonObjects()
    {
        $header = json_encode([1,2,3]);
        $header = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($header));
        $payload = json_encode([4,5,6]);
        $payload = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($payload));

        $decoder = new JwsDecoder();
        $this->expectException(InvalidJwtFormatException::class);
        $this->expectExceptionMessage("JWS contains invalid Json.");
        $decoder->decode("$header.$payload.");
    }

    public function testTokenHeaderDoesNotContainAlgParam()
    {
        $header = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode("{}"));
        $payload = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode("{}"));

        $decoder = new JwsDecoder();
        $this->expectException(InvalidAlgorithmException::class);
        $this->expectExceptionMessage("Invalid algorithm 'undefined'.");
        $decoder->decode("$header.$payload.");
    }

    public function testTokenHeaderDoesNotContainValidAlgValue()
    {
        $header = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode('{"alg":"fail"}'));
        $payload = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode("{}"));

        $decoder = new JwsDecoder();
        $this->expectException(InvalidAlgorithmException::class);
        $this->expectExceptionMessage("Invalid algorithm 'fail'.");
        $decoder->decode("$header.$payload.");
    }

    public function testTokenHeaderDoesNotContainCriticalParameter()
    {
        $header = [
            'alg' => 'none',
            'crit' => ['fail']
        ];
        $header = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode(json_encode($header)));
        $payload = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode("{}"));

        $decoder = new JwsDecoder();
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessage("Critical Header parameter 'fail' is missing or not supported.");
        $decoder->decode("$header.$payload.");
    }

    public function testTokenHeaderContainsUnsupportedCriticalParameter()
    {
        $header = [
            'alg' => 'none',
            'crit' => ['try'],
            'try' => 'fail'
        ];
        $header = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode(json_encode($header)));
        $payload = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode("{}"));

        $decoder = new JwsDecoder();
        $this->expectException(InvalidHeaderException::class);
        $this->expectExceptionMessage("Critical Header parameter 'try' is missing or not supported.");
        $decoder->decode("$header.$payload.");
    }

}
