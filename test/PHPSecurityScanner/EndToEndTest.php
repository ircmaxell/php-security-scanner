<?php

/*
 * This file is part of PHP-Security-Scanner, a static security analyzer for PHP
 *
 * @copyright 2015 Anthony Ferrara. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */

namespace PHPSecurityScanner;

use PHPCfg\Parser as CFGParser;
use PHPCfg\Traverser;
use PHPCfg\Visitor;
use PhpParser\ParserFactory;

class EndToEndTest extends \PHPUnit_Framework_TestCase {
    
    public static function provideTest() {
        $it = new \CallbackFilterIterator(
                new \RecursiveIteratorIterator(
                    new \RecursiveDirectoryIterator(__DIR__ . "/../code/")
                ),
                function ($file) {
                    return $file->getExtension() === 'php';
                }
        );
        $tests = [];
        foreach ($it as $file) {
            $tests[] = array_merge([basename($file)], require($file));
        }
        return $tests;
    }

    private $analyzer;
    private $parser;
    private $traverser;

    public function setUp() {
        $this->analyzer = new Command\Scan;
        $this->parser = new CFGParser((new ParserFactory)->create(ParserFactory::PREFER_PHP7));
        $this->traverser = new Traverser;
        $this->traverser->addVisitor(new Visitor\Simplifier);
    }

    /**
     * @dataProvider provideTest
     */
    public function testAll($file, $code, $expected) {
        $blocks = [$this->traverser->traverse($this->parser->parse($code, "file.php"))];
        ob_start();
        $components = $this->analyzer->analyzeGraphs($blocks);
        $rules = [];
        $rules[] = new Rule\MySQLQuery;
        $errors = [];
        foreach ($rules as $rule) {
            $errors = array_merge($errors, $rule->execute($components));
        }
        $results = [];
        foreach ($errors as $tmp) {
            $results[] = [
                "line"    => $tmp[1]->getLine(),
                "message" => $tmp[0],
            ];
        }
        $output = ob_get_clean();
        $sort = function($a, $b) {
            if ($a['line'] !== $b['line']) {
                return $a['line'] - $b['line'];
            }
            return strcmp($a['message'], $b['message']);
        };
        usort($expected, $sort);
        usort($results, $sort);
        $this->assertEquals($expected, $results);
    }

}