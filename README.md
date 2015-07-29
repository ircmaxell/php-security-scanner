# A Static Analyzer Security Scanner (for PHP)

This detects passing unsafe variables to unsafe function arguments.

## Usage:

    bin/php-security-scanner scan path/to/files

It will search through all files for security issues.

## Example

Given the following code:

```php
<?php

function bar() {
	foo($_GET['name']);
}

function foo($name) {
	mysql_query("SELECT * FROM foo WHERE name = '$name'");
}

?>
```

Running the scanner on this file will identify like 4 as an error, with the message:

> Possible SQL Injection found in call to foo() argument number 1

## Supported vulnerability scanners:

Currently, only `mysql_query` is supported, and only in limited situations.