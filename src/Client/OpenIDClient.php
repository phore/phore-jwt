<?php
/**
 * Created by PhpStorm.
 * User: matthias
 * Date: 09.07.20
 * Time: 11:41
 */

namespace Phore\JWT\Client;


use Phore\Cache\Cache;
use Phore\Cache\CacheItemPool;
use Phore\JWT\Exceptions\NoTokenException;
use Phore\JWT\JWK\JwkFactory;
use Phore\JWT\JWK\Jwks;
use Phore\JWT\JwsDecoder;
use Phore\JWT\Jwt;

class OpenIDClient
{


    protected $config = [
        "ttl.openid-config" => 1200,
        "expires.openid-config" => 86400,
        "ttl.jwks" => 1200,
        "expires.jwks" => 86400,
        "token.renew-before-expires" => 1200
    ];

    /**
     * @var array
     */
    protected $openIdConfig;

    /**
     * @var CacheItemPool
     */
    protected $cacheItemPool;

    protected $clientId;

    protected $clientSecret;


    protected $tokenLoader = null;


    public function __construct(array $openIdConfig, CacheItemPool $cacheItemPool)
    {
        $this->openIdConfig = $openIdConfig;
        $this->cacheItemPool = $cacheItemPool;

    }



    public function setClientId(string $clientId, string $clientSecret) : self
    {
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
        return $this;
    }


    public function setLogger()
    {

    }


    /**
     * Define the function to aquire the current token
     *
     * By default the current token will be loaded from Authentication: Bearer header.
     *
     * @param callable $fn
     * @return OpenIDClient
     */
    public function setTokenLoader(callable $fn) : self
    {
        $this->tokenLoader = $fn;
        return $this;
    }


    public function getJwks() : Jwks
    {
        $url = phore_pluck("jwks_uri", $this->openIdConfig, new \InvalidArgumentException("jwks_uri not defined in openid config"));

        $item = $this->cacheItemPool->getItem("openid_jwks_$url");

        $jwkData = $item->load(function () use ($url) {
            return phore_http_request($url)->send()->getBodyJson();
        });
        $factory = new JwkFactory();
        return $factory->buildJwks($jwkData);
    }


    /**
     * Request a token for the clientId (Client Auth Stream)
     *
     * Will return a cached JWT
     *
     * @param array $requestScopes
     * @return Jwt
     */
    public function getClientToken(array $requestScopes=[]) : Jwt
    {
        $url = phore_pluck("token_endpoint", $this->openIdConfig, new \InvalidArgumentException("token_endpoint not defined in openid config"));

        $item = $this->cacheItemPool->getItem("openid_{$url}_{$this->clientId}_" . implode("/", $requestScopes));

        $token = $item->load(function () {
            // do the call here
        });

        return new Jwt();

    }


    protected function loadBearerTokenFromHttpHeader()
    {
        $header = null;
        if (isset($_SERVER["Authorization"])) {
            $header = $_SERVER["Authorization"];
        } else if (isset ($_SERVER["HTTP_AUTHORIZATION"])) {
            $header = $_SERVER["HTTP_AUTHORIZATION"];
        }
        if ($header === null)
            return null;

        if (preg_match("/^Bearer\s(.*)$/i", trim($header), $matches))
            return $matches[1];
        return null;
    }



    /**
     * Return the validated Token from the request
     *
     * If the token is not specified, run the callable defined in
     * setTokenLoader(). If this is not set, it will get the token
     * from Authentication: Bearer HTTP Header.
     *
     * @param string|null $token
     * @return Jwt
     */
    public function getValidatedToken(string $token=null) : Jwt
    {
        $decoder = new JwsDecoder();

        if ($token === null) {
            if ($this->tokenLoader !== null) {
                $token = ($this->tokenLoader)();
            } else {
                $token = $this->loadBearerTokenFromHttpHeader();
            }
        }
        if ($token === null)
            throw new NoTokenException("No JWT token was supplied.");


        $decoder->setJwks($this->getJwks());
        $decoder->setClientId($this->clientId);

        $jwt = $decoder->decode($token);
        return $jwt;

    }
}

