<?php

namespace App;


use Phore\JWT\JwtEncoder;
use Phore\JWT\JwtToken;

$token = new JwtToken();
$encoder = new JwtEncoder();
$encoder->setAlg("abc");
$jws = $encoder->encode($token);
