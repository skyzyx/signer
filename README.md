# Signer

[![Source](http://img.shields.io/badge/source-skyzyx/signer-blue.svg?style=flat-square)](https://github.com/skyzyx/signer)
[![Latest Stable Version](http://img.shields.io/packagist/v/skyzyx/signer.svg?style=flat-square)](https://packagist.org/packages/skyzyx/signer)
[![Total Downloads](http://img.shields.io/packagist/dt/skyzyx/signer.svg?style=flat-square)](https://packagist.org/packages/skyzyx/signer)
[![Open Issues](http://img.shields.io/github/issues/skyzyx/signer.svg?style=flat-square)](https://github.com/skyzyx/signer)  
[![Build Status](http://img.shields.io/travis/skyzyx/signer/master.svg?style=flat-square)](https://travis-ci.org/skyzyx/signer)
[![Coverage Status](http://img.shields.io/coveralls/skyzyx/signer/master.svg?style=flat-square)](https://coveralls.io/r/skyzyx/signer?branch=master)
[![Code Climate](http://img.shields.io/codeclimate/github/skyzyx/signer.svg?style=flat-square)](https://codeclimate.com/github/skyzyx/signer)
[![Code Quality](http://img.shields.io/scrutinizer/g/skyzyx/signer.svg?style=flat-square)](https://scrutinizer-ci.com/g/skyzyx/signer)
[![Dependency Status](https://www.versioneye.com/user/projects/54483c0839f096d562000068/badge.svg?style=flat-square)](https://www.versioneye.com/user/projects/54483c0839f096d562000068)
[![HHVM Support](http://img.shields.io/hhvm/skyzyx/signer.svg?style=flat-square)](https://hhvm.com)  
[![MIT License](http://img.shields.io/packagist/l/skyzyx/signer-blue.svg?style=flat-square)](https://packagist.org/packages/skyzyx/signer)
[![Author](http://img.shields.io/badge/author-@skyzyx-blue.svg?style=flat-square)](https://twitter.com/skyzyx)

The **Signer** class is designed for those who are signing data on behalf of a public-private keypair.

In principle, the "client party" has public key (i.e., `client_id`) has a matching private key (i.e., `client_secret`) that can be verified by both the signer, as well as the client, but by nobody else as we don't want to make forgeries possible.

The "signing party" has a simple an identifier which acts as an additional piece of entropy in the algorithm, and can help differentiate between multiple signing parties if the client party does something like try to use the same public-private keypair independently of a signing party (as is common with GPG signing).

For example, in the original AWS implementation, the "self key" for AWS was `AWS4`.


## Examples

```php
use Skyzyx\Signer\Signer;

$self_key = 'Skyzyx';
$client_id = 'k3qDQy0Tr56v1ceo';
$client_secret = 'O5j@pG@Jt%AzyiJTEfo!£LSz8yqSj)JX)S6FvW%58KjlS9bc%Fi7&&C4KSCT8hxd';

$signer = new Signer($self_key, $client_id, $client_secret, 'sha512');
$signature = $signer->sign([
    'ClientID' => $client_id,
    'Domain' => 'foo.com',
    'Path' => '/',
    'Expires' => 'Wed, 13 Jan 2021 22:23:01 GMT',
    'Secure' => null,
    'HttpOnly' => null,
]);

$signature = wordwrap($signature, 64, "\n", true);
#=> dfbffab5b6f7156402da8147886bba3eba67bd5baf2e780ba9d39e8437db7c47
#=> 35e9a0b834aa21ac76f98da8c52a2a0cd1b0192d0f0df5c98e3848b1b2e1a037
```


## Features

* SHA-512 signatures.
* Based on a simplified version of the AWS Signature v4.


## Installation

Using [Composer]:
```bash
composer require skyzyx/signer=~1.0
```

And include it in your scripts:

```php
require_once 'vendor/autoload.php';
```


## Testing

Firstly, run `composer install -o` to download and install the dependencies.

You can run the tests as follows:
```bash
./vendor/bin/phpunit
```


## API Reference

The API Reference is generated by a tool called [phpDocumentor 2.x](http://phpdoc.org). You should install it locally
on your system with:

```bash
cd /usr/local/bin &&
wget http://phpdoc.org/phpDocumentor.phar &&
chmod +x phpDocumentor.phar &&
mv phpDocumentor.phar phpdoc
```

Once it's installed, you can generate updated documentation by running the following command in the root of the
repository.
```bash
phpdoc
```


## Contributing
Here's the process for contributing:

1. Fork Signer to your GitHub account.
2. Clone your GitHub copy of the repository into your local workspace.
3. Write code, fix bugs, and add tests with 100% code coverage.
4. Commit your changes to your local workspace and push them up to your GitHub copy.
5. You submit a GitHub pull request with a description of what the change is.
6. The contribution is reviewed. Maybe there will be some banter back-and-forth in the comments.
7. If all goes well, your pull request will be accepted and your changes are merged in.


## Authors, Copyright & Licensing

* Copyright (c) 2011-2014 [Amazon Web Services, Inc.](http://aws.amazon.com)
* Copyright (c) 2014 [Ryan Parman](http://ryanparman.com).

See also the list of [contributors](/skyzyx/signer/contributors) who participated in this project.

Licensed for use under the terms of the [Apache 2.0] license.

  [PHP]: http://php.net
  [Composer]: https://getcomposer.org
  [MIT]: http://www.opensource.org/licenses/mit-license.php
  [Apache 2.0]: http://opensource.org/licenses/Apache-2.0


## Coding Standards

* <https://github.com/skyzyx/php-coding-standards>

  [PHP]: http://php.net
  [Composer]: https://getcomposer.org
  [MIT]: http://www.opensource.org/licenses/mit-license.php
  [Apache 2.0]: http://opensource.org/licenses/Apache-2.0
