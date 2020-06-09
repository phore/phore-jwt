<?php

namespace Phore\JWT;

class JWT
{

    public $header;
    public $payload;

    /**
     * JwtToken constructor.
     * @param mixed[] $header
     * @param mixed[] $payload
     */
    public function __construct(array $payload = [], array $header = [])
    {
        $this->header = $header;

        // Should be ignored by libraries - TEST!
        $this->header["typ"] = "JWT";

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
