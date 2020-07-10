<?php
/**
 * Created by PhpStorm.
 * User: matthias
 * Date: 09.07.20
 * Time: 11:56
 */

namespace Phore\JWT;


class JwtValidator
{


    public function __construct(Jwt $jwt, callable $onValidationFailedHandler=null)
    {
    }


    public function getJwt() : Jwt
    {

    }


    public function requireClaim(string $claim)
    {

    }

    public function requireOneOfClaims(array $claims)
    {

    }

    public function requireAllClaims(array $claims)
    {

    }


    public function requireClaimMatch(string $claim)
    {

    }

    public function requireClaimValueContains(string $claim, string $value)
    {

    }


    public function requireClaimValueEquals(string $claim, string $value)
    {

    }

}
