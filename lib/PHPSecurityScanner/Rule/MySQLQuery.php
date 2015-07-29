<?php

/*
 * This file is part of PHP-Security-Scanner, a static security analyzer for PHP
 *
 * @copyright 2015 Anthony Ferrara. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */

namespace PHPSecurityScanner\Rule;

use PHPCfg\Op;
use PHPCfg\Operand;
use PHPTypes\State;
use Tuli\Rule;

class MySQLQuery implements Rule {

    public function getName() {
        return "mysql_query() injection";
    }

    public function execute(State $state) {
        $toCheck = [["mysql_query", 0]];
        $checked = [];
        $errors = [];
        while (!empty($toCheck)) {
            list($func, $argNum) = array_shift($toCheck);
            $printableArgNum = $argNum + 1;
            echo "Scanning {$func}() argument number {$printableArgNum}\n";
            $checked[] = $toCheck;
            foreach ($state->callFinder->getCallsForFunction($func) as $call) {

                if (!$this->processQueryArg($call[0]->args[$argNum])) {
                    $errors[] = ["Possible SQL Injection found in call to {$func}() argument number {$printableArgNum}", $call[0]];
                }
                if ($call[1]) {
                    foreach ($call[1]->getParams() as $i => $param) {
                        if ($param->getAttribute("unsafe", false) && !isset($checked[$call[1]->name->value])) {
                            $toCheck[] = [$call[1]->name->value, $i];
                        }
                    }
                }
            }
        }
        return $errors;
    }

    private function processQueryArg(Operand $arg) {
        if ($arg instanceof Operand\Literal) {
            // Literal queries are always OK
            return true;
        }
        // Otherwise, we need to look up where the arg came from
        $i = 0;
        foreach ($arg->ops as $prev) {
            $i++;
            if (!$this->processQueryArgOp($prev)) {
                return false;
            }
        }
        if ($i > 0) {
            return true;
        }
        // We don't know the source
        return false;
    }

    private function processQueryArgOp(Op $op) {
        static $seen;
        if ($seen === null) {
            $seen = new \SplObjectStorage;
        }
        if ($seen->contains($op)) {
            return $seen[$op];
        }
        $seen[$op] = false;
        switch ($op->getType()) {
            case 'Expr_ArrayDimFetch':
                return $seen[$op] = $this->processQueryArg($op->var);
            case 'Expr_Assign':
                return $seen[$op] = $this->processQueryArg($op->expr);
            case 'Expr_ConcatList':
                foreach ($op->list as $el) {
                    if (!$this->processQueryArg($el)) {
                        return $seen[$op] = false;
                    }
                }
                return $seen[$op] = true;
            case 'Expr_BinaryOp_Concat':
                if (!$this->processQueryArg($op->left)) {
                    return $seen[$op] = false;
                }
                if (!$this->processQueryArg($op->right)) {
                    return $seen[$op] = false;
                }
                return $seen[$op] = true;
            case 'Expr_FuncCall':
                if ($op->name instanceof Operand\Literal && $op->name->value === "mysql_real_escape_string") {
                    return $seen[$op] = true;
                }
                return $seen[$op] = false;
            case 'Expr_Param':
                $unsafe = true;
                $op->setAttribute("unsafe", $unsafe);
                return $seen[$op] = true;
            case 'Phi':
                // assume it's safe
                $seen[$op] = true;
                foreach ($op->vars as $var) {
                    if (!$this->processQueryArg($var)) {
                        return $seen[$op] = false;
                    }
                }
                return $seen[$op] = true;
            default:
                throw new \RuntimeException("Unknown OP Type: " . $op->getType());
        }
        
    }

}