<?php

namespace App;

/**
 * - API
 * - Project Setup for T4S-STORE
 * - Extend T4s with User List
 * - Talk about OHT Time adjust
 * - Deployment Status of Kubernetes
 *
 * https://tools.ietf.org/html/rfc7519#section-7.1 - CREATE JWT
 *
 */

use Phore\JWT\JwtEncoder;
use Phore\JWT\Jwt;


/* CREATE a Token */

$token = new Jwt([
    "sub" => "alskdj",
    "..." => "..."
]);

/* Syncronous Key */

$encoder = new JwtEncoder();
$encoder->setAlg("HS256");
$encoder->setSecretKey("secretKey");

$jws = $encoder->encode($token);


/* Asyncronous Key */

$encoder = new JwtEncoder();
$encoder->setAlg("RS256");
$encoder->setPrivateKey("privatekey");

$jws = $encoder->encode($token);


/* JWKS */

$jwks = new JWKS();
$jwks->addKey("keyId1", "privateKey");
$jwks->addKey("keyId2", "privateKey2");


$encoder = new JwtEncoder();
$encoder->setJwks($jwks);
$encoder->setJwksKeyId("keyId1");

$jws = $encoder->encode($token);

/* Output the jwks.json */

$jwks->generateJwksJson();







