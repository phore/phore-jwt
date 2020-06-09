<?php
/**
 * Created by PhpStorm.
 * User: matthias
 * Date: 09.06.20
 * Time: 13:32
 */

namespace Demo;


/* Client Side */


use Phore\JWT\JwtDecoder;

$jwks = new Jwks();
$jwks->addPublicKeysFromUrl("https://xxxx");
$jwks->addKeySet($keyset);


$decoder = new JwtDecoder();
$decoder->addJwks($jwks);

$token = $decoder->decode($stringInput);




/* Load Key by token */

$decoder = new JwtDecoder();

$decoder->setOnBeforeDecode(function (JwtDecoder $decoder, JWT $unverifiedToken) {
    $decoder->addPrivateKey(file_get_contents($unverifiedToken->data->iss));
});

$decoder->setPublicKeyLoader(function (JWT $unverifiedToken) {
    return file_get_contents($token->body->iss . ".pubkey");
});

$token = $decoder->decode($stringInput);

/*
$unverifiedToken = $decoder->decodeUnverified($stringInput);
$key = file_get_contents($unverifiedToken->body->iss);
$decoder->addKey($key);
$decoder->verifyToken($unverifiedToken);
*/



/* Syncronous Key */

$decoder = new JwtDecoder();
$decoder->addSyncronousKey("issuer1", "secret1");





/* OpenId */

$decoder = new JwtDecoder();

$decoder->addJwks($jwks);

// Will scan for .well-known/openid-configuration
$decoder->addTrustedIssuer("https://t4s.login");
$decoder->addTrustedIssuer("https://otherls.login");
$decoder->allowMaxLifetime(86400);

$decoder->addRequiredClaims([
    "abc:abc:abc"
]);


/* Assume: KIds are global unique IDS */

try {
    $token = $decoder->decode($stingInput);

    $token->requireScopes([
        "scope1", "scope2"
    ]);


    $token->hasScope("someScope");

} catch (InvalidTokenException $e) {
    // Triggered if unauthorized server / Invalid signature etc.
} catch (TokenTimeoutException $e) {
    // If token is timed out
} catch (RequiredClaimsMissingException $e) {

}
