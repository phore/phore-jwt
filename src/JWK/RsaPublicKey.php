<?php


namespace Phore\JWT\JWK;


use Phore\ASN\DerPacker;
use Phore\ASN\PemFormatHelper;

class RsaPublicKey extends Jwk
{
    private $modulus;
    private $exponent;

    /**
     * RsaPublicKey constructor.
     * @param string $modulus n - binary string
     * @param string $exponent e - binary string
     */
    public function __construct(string $modulus, string $exponent)
    {
        $keyType = 'RSA';
        parent::__construct($keyType);
        $this->modulus = $modulus;
        $this->exponent = $exponent;
    }

    public function getPem(): string
    {
        return $this->getPemEncodedString() ?? $this->pemEncodeKey();

    }

    private function pemEncodeKey() : string
    {
        $oid = "300d06092a864886f70d0101010500";
        $derMod = DerPacker::packUnsignedInt(bin2hex($this->modulus));
        $derExp = DerPacker::packUnsignedInt(bin2hex($this->exponent));
        $derModExp = DerPacker::packSequence($derMod, $derExp);
        $derPubKeyBitString = DerPacker::packBitString($derModExp, "00");
        $derEncodedKey = DerPacker::packSequence($oid, $derPubKeyBitString);

        $label = 'PUBLIC KEY';
        return PemFormatHelper::pemEncodeKey($derEncodedKey, $label);

//        $header = "-----BEGIN {$label}-----\n";
//        $footer = "-----END {$label}-----\n";
//        $base64Key = base64_encode(hex2bin($derEncodedKey));
//        $data = chunk_split($base64Key,64, "\n");
//        return trim($header . $data . $footer);

    }

    protected function getKeyComponentArray(): array
    {
        $jwk['n'] = base64urlEncode($this->modulus);
        $jwk['e'] = base64urlEncode($this->exponent);
        return $jwk;
    }

    protected function getThumbprintArray(): array
    {
        $thumbprint = $this->getKeyComponentArray();
        $thumbprint['kty'] = $this->keyType;
        return $thumbprint;
    }
}
