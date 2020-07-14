<?php
/**
 * Created by PhpStorm.
 * User: matthias
 * Date: 10.07.20
 * Time: 11:49
 */

namespace Phore\JWT\Client;


use Phore\Cache\CacheItemPool;
use Phore\Tests\OpenIdAuthFlowTest;

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



    protected function getDiscoveryConfig(string $openIdHost, string $discoveryPath = "/.well-known/openid-configuration.json")
    {
        $cache = $this->cacheItemPool->getItem("openid_{$openIdHost}_{$discoveryPath}");

        $config = $cache->load(function() use ($openIdHost, $discoveryPath) {
            return phore_http_request("{$openIdHost}{$discoveryPath}")->send()->getBodyJson();
        });
        return $config;
    }

    /**
     * Return OpenID Client for webservice token verification
     *
     * @param string $openIdHost
     * @param string $discoveryPath
     * @return OpenIDClient
     */
    public function getOpenIdClient(string $openIdHost, string $discoveryPath="/.well-known/openid-configuration.json") : OpenIDClient
    {
        $config = $this->getDiscoveryConfig($openIdHost, $discoveryPath);
        return new OpenIDClient($config, $this->cacheItemPool);
    }


    /**
     * Return OpenID Client for Resource Owner (Frontend) usage
     *
     * @param string $openIdHost
     * @param string $discoveryPath
     * @return OpenIDAuthFlowClient
     */
    public function getOpenIdAuthFlowClient(string $openIdHost, string $discoveryPath="/.well-known/openid-configuration.json") : OpenIDAuthFlowClient
    {
        $config = $this->getDiscoveryConfig();
        return new OpenIDAuthFlowClient($config, $this->cacheItemPool);
    }

}
