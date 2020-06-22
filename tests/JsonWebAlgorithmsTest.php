<?php


use Phore\JWT\JsonWebAlgorithms;
use PHPUnit\Framework\TestCase;

class JsonWebAlgorithmsTest extends TestCase
{
    public function testIsValidJWA()
    {
        $this->assertFalse(JsonWebAlgorithms::isValid('undefined'));
        $this->assertTrue(JsonWebAlgorithms::isValid(JsonWebAlgorithms::RS256));
    }

}
