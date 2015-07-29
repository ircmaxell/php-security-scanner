<?php

/*
 * This file is part of PHP-Security-Scanner, a static security analyzer for PHP
 *
 * @copyright 2015 Anthony Ferrara. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */

$code = <<<'EOF'
<?php
function foo() {
	mysql_query($_GET["query"]);
}
?>
EOF;

return [
    $code,
    [
        [
            "line"    => 3,
            "message" => "Possible SQL Injection found in call to mysql_query() argument number 1",
        ]
    ]
];