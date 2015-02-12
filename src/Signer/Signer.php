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

use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerAwareTrait;
use Psr\Log\LoggerTrait;
use Psr\Log\NullLogger;

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
class Signer implements SignerInterface, LoggerAwareInterface
{
    use LoggerAwareTrait;


    /**************************************************************************/
    // PROPERTIES

    /** @var string */
    private $self_key;

    /** @var string */
    private $client_id;

    /** @var string */
    private $client_secret;

    /** @var string */
    private $hash_algo = '';


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
     * @param string $hash_algo     The hash algorithm to use for signing. Run `hash_algos()` to see what's supported.
     *                              The default value is `sha512`.
     *
     * @see http://php.net/hash_algos
     */
    public function __construct($self_key, $client_id, $client_secret, $hash_algo = 'sha512')
    {
        $this->self_key      = $self_key;
        $this->client_id     = $client_id;
        $this->client_secret = $client_secret;
        $this->hash_algo     = $hash_algo;
        $this->logger        = new NullLogger();
    }

    /**
     * {@inheritdoc}
     */
    public function getSelfKey()
    {
        /** @var string */
        return $this->self_key;
    }

    /**
     * {@inheritdoc}
     */
    public function getClientId()
    {
        /** @var string */
        return $this->client_id;
    }

    /**
     * {@inheritdoc}
     */
    public function getClientSecret()
    {
        /** @var string */
        return $this->client_secret;
    }

    /**
     * {@inheritdoc}
     */
    public function sign(array $payload)
    {
        $scope       = $this->createScope($this->getSelfKey(), $this->getClientId());
        $context     = $this->createContext($payload);
        $s2s         = $this->createStringToSign($this->getSelfKey(), $this->getClientId(), $scope, $context);
        $signing_key = $this->getSigningSalt($this->getSelfKey(), $this->getClientId(), $this->getClientSecret());
        $signature   = hash_hmac($this->hash_algo, $s2s, $signing_key);

        /** @var string */
        return $signature;
    }


    /**************************************************************************/
    // PRIVATE METHODS

    /**
     * Creates the string-to-sign based on a variety of factors.
     *
     * @param  string $self_key  A string which identifies the signing party and adds additional entropy.
     * @param  string $client_id A string which is the public portion of the keypair identifying the client party.
     * @param  string $scope     The results of a call to the `createScope()` method.
     * @param  string $context   The results of a call to the `createContext()` method.
     * @return string The final string to be signed.
     */
    private function createStringToSign($self_key, $client_id, $scope, $context)
    {
        $s2s = sprintf(
            "SIGNER-HMAC-%s\n%s\n%s\n%s\n%s",
            strtoupper($this->hash_algo),
            $self_key,
            $client_id,
            hash($this->hash_algo, $scope),
            hash($this->hash_algo, $context)
        );

        $this->logger->debug(__FUNCTION__, [
            'string_to_sign' => $s2s,
        ]);

        /** @var string */
        return $s2s;
    }

    /**
     * An array of key-value pairs representing the data that you want to sign.
     * All values must be `scalar`.
     *
     * @param  array  $payload The data that you want to sign.
     * @return string A canonical string representation of the data to sign.
     */
    private function createContext(array $payload)
    {
        $canonical_payload = [];

        foreach ($payload as $k => $v) {
            $k = strtolower($k);
            $v = strtolower($v);

            $canonical_payload[$k] = sprintf('%s=%s', $k, $v);
        }

        ksort($canonical_payload);
        $signed_headers_string = implode(';', array_keys($canonical_payload));
        $canonical_context     = implode("\n", $canonical_payload) . "\n\n" . $signed_headers_string;

        $this->logger->debug(__FUNCTION__, [
            'payload' => $payload,
            'canonical_payload' => $canonical_payload,
            'signed_headers_string' => $signed_headers_string,
            'canonical_context' => $canonical_context,
        ]);

        /** @var string */
        return $canonical_context;
    }

    /**
     * Gets the salt value that should be used for signing.
     *
     * @param  string $self_key      A string which identifies the signing party and adds additional entropy.
     * @param  string $client_id     A string which is the public portion of the keypair identifying the client party.
     * @param  string $client_secret A string which is the private portion of the keypair identifying the client party.
     * @return string The signing salt.
     */
    private function getSigningSalt($self_key, $client_id, $client_secret)
    {
        $self_key_sign  = hash_hmac($this->hash_algo, $self_key, $client_secret, true);
        $client_id_sign = hash_hmac($this->hash_algo, $client_id, $self_key_sign, true);
        $salt           = hash_hmac($this->hash_algo, 'signer', $client_id_sign, true);

        $this->logger->debug(__FUNCTION__, [
            'input'  => [
                'self_key'       => $self_key,
                'client_id'      => $client_id,
                'client_secret'  => $client_secret,
            ],
            'output' => [
                'self_key_sign'  => $self_key_sign,
                'client_id_sign' => $client_id_sign,
                'salt'           => $salt,
            ],
        ]);

        /** @var string */
        return $salt;
    }

    /**
     * Creates the "scope" in which the signature is valid.
     *
     * @param  string $self_key  A string which identifies the signing party and adds additional entropy.
     * @param  string $client_id A string which is the public portion of the keypair identifying the client party.
     * @return string The string which represents the scope in which the signature is valid.
     */
    private function createScope($self_key, $client_id)
    {
        $scope = sprintf(
            '%s/%s/signer',
            $self_key,
            $client_id
        );

        $this->logger->debug(__FUNCTION__, [
            'scope' => $scope,
        ]);

        /** @var string */
        return $scope;
    }
}
