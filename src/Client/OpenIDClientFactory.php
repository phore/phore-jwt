<?php
/**
 * Created by PhpStorm.
 * User: matthias
 * Date: 10.07.20
 * Time: 11:49
 */

namespace Phore\JWT\Client;


use Phore\Cache\CacheItemPool;

class OpenIDClientFactory
{

    /**
     * @var CacheItemPool
     */
    protected $cacheItemPool;

    public function __construct()
    {
        $this->cacheItemPool = new CacheItemPool("file:///tmp", true);
        $this->cacheItemPool->setDefaultRetryAfter(3600);
        $this->cacheItemPool->setDefaultExpiresAfter(86400);
    }


    public function setCacheItemPool(CacheItemPool $cacheItemPool)
    {
        $this->cacheItemPool = $cacheItemPool;
    }


    public function getOpenIdClient(string $openIdHost, string $discoveryPath="/.well-known/openid-configuration.json") : OpenIDClient
    {
        $cache = $this->cacheItemPool->getItem("openid_{$openIdHost}_{$discoveryPath}");

        $config = $cache->load(function() use ($openIdHost, $discoveryPath) {
            return phore_http_request("{$openIdHost}{$discoveryPath}")->send()->getBodyJson();
        });

        return new OpenIDClient($config, $this->cacheItemPool);
    }

}
