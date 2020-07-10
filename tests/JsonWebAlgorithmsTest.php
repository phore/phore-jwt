<?php

namespace Phore\Tests;

use Phore\JWT\Jwa;
use PHPUnit\Framework\TestCase;

class JsonWebAlgorithmsTest extends TestCase
{
    public function testIsValidJWA()
    {
        $this->assertFalse(Jwa::isValid('undefined'));
        $this->assertTrue(Jwa::isValid(Jwa::RS256));
    }

}
