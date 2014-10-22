<?php
/**
 * Copyright (c) 2014 Ryan Parman.
 *
 * http://opensource.org/licenses/Apache2.0
 */

namespace Skyzyx\Test\Signer;

use \PHPUnit_Framework_TestCase;
use Skyzyx\Signer\Signer;

class SignerTest extends PHPUnit_Framework_TestCase
{
    const DEFAULT_SELF_KEY = 'Skyzyx';
    const DEFAULT_CLIENT_ID = 'k3qDQy0Tr56v1ceo';
    const DEFAULT_CLIENT_SECRET = 'O5j@pG@Jt%AzyiJTEfo!£LSz8yqSj)JX)S6FvW%58KjlS9bc%Fi7&&C4KSCT8hxd';
    const DEFAULT_SIGNATURE = "dfbffab5b6f7156402da8147886bba3eba67bd5baf2e780ba9d39e8437db7c4735e9a0b834aa21ac76f98da8c52a2a0cd1b0192d0f0df5c98e3848b1b2e1a037";

    public $signer = '';

    public function setUp()
    {
        $this->signer = new Signer(self::DEFAULT_SELF_KEY, self::DEFAULT_CLIENT_ID, self::DEFAULT_CLIENT_SECRET);
    }

    public function testAttributes()
    {
        $this->assertEquals(self::DEFAULT_SELF_KEY, $this->readAttribute($this->signer, 'self_key'));
        $this->assertEquals(self::DEFAULT_CLIENT_ID, $this->readAttribute($this->signer, 'client_id'));
        $this->assertEquals(self::DEFAULT_CLIENT_SECRET, $this->readAttribute($this->signer, 'client_secret'));
    }

    public function testGetSelfKey()
    {
        $this->assertEquals(self::DEFAULT_SELF_KEY, $this->signer->getSelfKey());
    }

    public function testGetClientKey()
    {
        $this->assertEquals(self::DEFAULT_CLIENT_ID, $this->signer->getClientId());
    }

    public function testGetClientSecret()
    {
        $this->assertEquals(self::DEFAULT_CLIENT_SECRET, $this->signer->getClientSecret());
    }

    public function testSign()
    {
        $signature = $this->signer->sign([
            'ClientID' => self::DEFAULT_CLIENT_ID,
            'Domain' => 'foo.com',
            'Path' => '/',
            'Expires' => 'Wed, 13 Jan 2021 22:23:01 GMT',
            'Secure' => null,
            'HttpOnly' => null,
        ]);

        $this->assertEquals(self::DEFAULT_SIGNATURE, $signature);
    }
}
