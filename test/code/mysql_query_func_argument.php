<?php

/*
 * This file is part of PHP-Security-Scanner, a static security analyzer for PHP
 *
 * @copyright 2015 Anthony Ferrara. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */

$code = <<<'EOF'
<?php

function bar() {
	foo($_GET['name']);
}

function foo($name) {
	mysql_query("SELECT * FROM foo WHERE name = '$name'");
}
?>
EOF;

return [
    $code,
    [
        [
            "line"    => 4,
            "message" => "Possible SQL Injection found in call to foo() argument number 1",
        ]
    ]
];