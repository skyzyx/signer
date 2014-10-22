<?php
/**
 * Copyright (c) 2011-2014 Amazon Web Services, Inc.
 * Copyright (c) 2014 Ryan Parman.
 *
 * Based on a stripped-down version of the AWS Signature v4 implementation,
 * built into the AWS SDK for PHP 3.0. Original authors:
 *
 * @author Michael Dowling <https://github.com/mtdowling>
 * @author Jeremy Lindblom <https://github.com/jeremeamia>
 *
 * http://opensource.org/licenses/Apache2.0
 */

namespace Skyzyx\Signer;

/**
 * The Signer class is designed for those who are signing data on behalf of a public-private keypair.
 *
 * In principle, the "client party" has public key (i.e., `client_id`) has a matching private key
 * (i.e., `client_secret`) that can be verified by both the signer, as well as the client, but
 * by nobody else as we don't want to make forgeries possible.
 *
 * The "signing party" has a simple an identifier which acts as an additional piece of entropy in the
 * algorithm, and can help differentiate between multiple signing parties if the client party does
 * something like try to use the same public-private keypair independently of a signing party
 * (as is common with GPG signing).
 *
 * For example, in the original AWS implementation, the "self key" for AWS was "AWS4".
 */
class Signer
{
    /**************************************************************************/
    // PROPERTIES

    /** @var string */
    private $self_key;

    /** @var string */
    private $client_id;

    /** @var string */
    private $client_secret;

    /** @var integer */
    private $cache_size = 0;


    /**************************************************************************/
    // PUBLIC METHODS

    /**
     * Constructs a new instance of this class.
     *
     * @param string $self_key      A string which identifies the signing party and adds additional entropy.
     * @param string $client_id     A string which is the public portion of the keypair identifying the client party.
     *                              The pairing of the public and private portions of the keypair should only be known
     *                              to the client party and the signing party.
     * @param string $client_secret A string which is the private portion of the keypair identifying the client party.
     *                              The pairing of the public and private portions of the keypair should only be known
     *                              to the client party and the signing party.
     */
    public function __construct($self_key, $client_id, $client_secret)
    {
        $this->self_key      = $self_key;
        $this->client_id     = $client_id;
        $this->client_secret = $client_secret;
    }

    /**
     * Gets the self key that was set in the constructor.
     *
     * @return string The self key.
     */
    public function getSelfKey()
    {
        return $this->self_key;
    }

    /**
     * Gets the client key that was set in the constructor.
     *
     * @return string The client key.
     */
    public function getClientId()
    {
        return $this->client_id;
    }

    /**
     * Gets the client secret that was set in the constructor.
     *
     * @return string The client secret.
     */
    public function getClientSecret()
    {
        return $this->client_secret;
    }

    public function sign(array $payload)
    {
        $scope = $this->createScope($this->getSelfKey(), $this->getClientId());
        $context = $this->createContext($payload);
        $s2s = $this->createStringToSign($this->getSelfKey(), $this->getClientId(), $scope, $context);
        $signing_key = $this->getSigningSalt(
            $this->getSelfKey(),
            $this->getClientId(),
            $this->getClientSecret()
        );

        $signature = hash_hmac('sha512', $s2s, $signing_key);

        return $signature;
    }


    /**************************************************************************/
    // PRIVATE METHODS

    public function createStringToSign($self_key, $client_id, $scope, $context)
    {
        return sprintf(
            "SIGNER-HMAC-SHA512\n%s\n%s\n%s\n%s",
            $self_key,
            $client_id,
            hash('sha512', $scope),
            hash('sha512', $context)
        );
    }

    /**
     * An array of key-value pairs representing the data that you want to sign.
     * All values must be `scalar`.
     *
     * @param  array  $payload The data that you want to sign.
     * @return string A canonical string representation of the data to sign.
     */
    public function createContext(array $payload)
    {
        $canonical_payload = [];

        foreach ($payload as $k => $v) {
            $k = strtolower($k);
            $v = strtolower($v);
            $canonical_payload[$k] = sprintf('%s=%s', $k, $v);
        }

        ksort($canonical_payload);
        $signed_headers_string = implode(';', array_keys($canonical_payload));
        $canon = implode("\n", $canonical_payload) . "\n\n" . $signed_headers_string;

        return $canon;
    }

    /**
     * Gets the salt value that should be used for signing.
     *
     * @param  string $self_key      A string which identifies the signing party and adds additional entropy.
     * @param  string $client_id     A string which is the public portion of the keypair identifying the client party.
     * @param  string $client_secret A string which is the private portion of the keypair identifying the client party.
     * @return string The signing salt.
     */
    public function getSigningSalt($self_key, $client_id, $client_secret)
    {
        $k = implode('_', [
            $self_key,
            $client_id,
            $client_secret
        ]);

        if (!isset($this->cache[$k])) {

            // Clear the cache when it reaches 50 entries
            if (++$this->cache_size > 50) {
                $this->cache = [];
                $this->cacheSize = 0;
            }

            $self_key_sign = hash_hmac('sha512', $self_key, $client_secret, true);
            $client_id_sign = hash_hmac('sha512', $client_id, $self_key_sign, true);
            $this->cache[$k] = hash_hmac('sha512', 'signer', $client_id_sign, true);
        }

        return $this->cache[$k];
    }

    /**
     * Creates the "scope" in which the signature is valid.
     *
     * @param  string $self_key  A string which identifies the signing party and adds additional entropy.
     * @param  string $client_id A string which is the public portion of the keypair identifying the client party.
     * @return string The string which represents the scope in which the signature is valid.
     */
    public function createScope($self_key, $client_id)
    {
        return sprintf(
            "%s/%s/signer",
            $self_key,
            $client_id
        );
    }
}
