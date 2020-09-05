<?php

namespace Phore\Tests;

use Phore\JWT\Jwa;
use Phore\JWT\JWK\Jwk;
use Phore\JWT\JWK\JwkFactory;
use Phore\JWT\JWK\Jwks;
use Phore\JWT\JWK\RsaPublicKey;
use PHPUnit\Framework\TestCase;

class JwksTest extends TestCase
{
    public function testGetSerializedJwks()
    {
        $rsaPrivateKey = JwkFactory::loadPem(trim(file_get_contents(__DIR__ . "/../mockData/secrets/private-key-rsa2048.pem")));
        $publicKey = $rsaPrivateKey->getPublicKey();
        $publicKey->setAlgorithm(Jwa::RS256);
        $jwks = new Jwks();
        $jwks->addJwk($publicKey);
        $expected = '{"keys":[{"kty":"RSA","use":"sig","alg":"RS256","kid":"68e9NEtuPfmUJ2EyH9RX95EFwb0oTGFWaBEHuMvChCI","n":"mswjKU7F8ZiPI9LdNrX79WopBnW9IF9l2VpQKWqwPOzIJAzxuTbKcb8glNYHleuJDlHrMhWpROq2DzWicS-uhkN3EYYAOdu5aJ-_t7XQirSnNzjLfb3QqEGLgY1d22AiCfRjhWGuY6ghaiRXuBIpCXrpB3f36cjD6Yk3ml1n2xFxplN3JFiO4QIPo-q50cSK4h80-C_JLlrcru5Y6KKnj3MapVI1QNDYTOzVZFdqT2GMZwKE5TKzljcKx70-JecCAQQ890_Up26ldU3ldc4ZhOC5yON_X-rto_0P0LBaWUqumvkF6_2e4vm2dAJI3PXqembcBL7ck0xKIdAvlgVBcQ","e":"D_9_"}]}';
        $this->assertEquals($expected, json_encode($jwks));
    }

//    private function getPubKey(Jwk $jwk): RsaPublicKey
//    {
//        return $jwk->getPublicKey();
//    }

}
