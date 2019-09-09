# Medoo Adapter for Casbin

[![Build Status](https://travis-ci.org/php-casbin/medoo-adapter.svg?branch=master)](https://travis-ci.org/php-casbin/medoo-adapter)
[![Coverage Status](https://coveralls.io/repos/github/php-casbin/medoo-adapter/badge.svg)](https://coveralls.io/github/php-casbin/medoo-adapter)
[![Latest Stable Version](https://poser.pugx.org/casbin/medoo-adapter/v/stable)](https://packagist.org/packages/casbin/medoo-adapter)
[![Total Downloads](https://poser.pugx.org/casbin/medoo-adapter/downloads)](https://packagist.org/packages/casbin/medoo-adapter)
[![License](https://poser.pugx.org/casbin/medoo-adapter/license)](https://packagist.org/packages/casbin/medoo-adapter)

[Medoo](https://github.com/catfan/Medoo) Adapter for [PHP-Casbin](https://github.com/php-casbin/php-casbin), [Casbin](https://casbin.org/) is a powerful and efficient open-source access control library.

`Medoo` is a lightweight PHP Database Framework to Accelerate Development, supports all SQL databases, including `MySQL`, `MSSQL`, `SQLite`, `MariaDB`, `PostgreSQL`, `Sybase`, `Oracle` and more.

### Installation

Via [Composer](https://getcomposer.org/).

```
composer require casbin/medoo-adapter
```

### Usage

```php

require_once './vendor/autoload.php';

use Casbin\Enforcer;
use CasbinAdapter\Medoo\Adapter as DatabaseAdapter;

$config = [
    'database_type' => 'mysql',
    'server' => '127.0.0.1',
    'database_name' => 'test',
    'username' => 'root',
    'password' => '',
    'port' => '3306',
];

$adapter = DatabaseAdapter::newAdapter($config);

$e = new Enforcer('path/to/model.conf', $adapter);

$sub = "alice"; // the user that wants to access a resource.
$obj = "data1"; // the resource that is going to be accessed.
$act = "read"; // the operation that the user performs on the resource.

if ($e->enforce($sub, $obj, $act) === true) {
    // permit alice to read data1
} else {
    // deny the request, show an error
}
```

### Getting Help

- [php-casbin](https://github.com/php-casbin/php-casbin)

### License

This project is licensed under the [Apache 2.0 license](LICENSE).