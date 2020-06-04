<?php

namespace Phore\JWT;

class JwtToken
{

    public $header;
    public $payload;

    /**
     * JwtToken constructor.
     * @param mixed[] $header
     * @param mixed[] $payload
     */
    public function __construct(array $header = ['alg' => "HS256", 'typ' => "JWT"], array $payload = [])
    {
        $this->header = $header;
        $this->payload = $payload;
    }


    public function setHeader($key, $value)
    {
        $this->header[$key] = $value;
    }

    public function setPayload($key, $value)
    {
        $this->payload[$key] = $value;
    }
}
