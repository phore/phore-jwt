<?php

namespace Phore\JWT;

class Jwt
{

    public $header;
    public $payload;
    public $signature;

    /**
     * JwtToken constructor.
     * @param mixed[] $claims Set of claims that will be added to the payload
     */
    public function __construct(array $claims = [])
    {
        // A valid JWT will always have the alg parameter
        $this->header["alg"] = "none";
        // Should be ignored by libraries - TEST!
        $this->header["typ"] = "JWT";

        $this->payload = $claims;
    }

    public function setHeader($key, $value)
    {
        $this->header[$key] = $value;
    }

    public function setClaim($key, $value)
    {
        $this->payload[$key] = $value;
    }

    public function serializeHeader() : string
    {
        return json_encode($this->header);
    }

    public function serializePayload() : string
    {
        return json_encode($this->payload);
    }

    public function getClaim($key, $default = null)
    {
        return $this->payload[$key] ?? $default;
    }

    public function getHeader($key, $default = null)
    {
        return $this->header[$key] ?? $default;
    }

//    public function get(string $name, $default = null)
//    {
//        return $this->data[$name] ?? $default;
//    }
//
//    public function has(string $name): bool
//    {
//        return array_key_exists($name, $this->data);
//    }
}
