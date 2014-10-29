<?php
/**
 * Copyright (c) 2014 Ryan Parman.
 *
 * http://opensource.org/licenses/Apache2.0
 */

namespace Skyzyx\Signer;

interface SignerInterface
{
    /**
     * Gets the self key that was set in the constructor.
     *
     * @return string The self key.
     */
    public function getSelfKey();

    /**
     * Gets the client key that was set in the constructor.
     *
     * @return string The client key.
     */
    public function getClientId();

    /**
     * Gets the client secret that was set in the constructor.
     *
     * @return string The client secret.
     */
    public function getClientSecret();

    /**
     * Sign the payload to produce a signature for its contents.
     *
     * @param  array  $payload The data to generate a signature for.
     * @return string The signature for the payload contents.
     */
    public function sign(array $payload);
}
