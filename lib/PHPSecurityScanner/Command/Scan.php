<?php

/*
 * This file is part of PHP-Security-Scanner, a static security analyzer for PHP
 *
 * @copyright 2015 Anthony Ferrara. All rights reserved
 * @license MIT See LICENSE at the root of the project for more info
 */

namespace PHPSecurityScanner\Command;

use PHPCfg\Op;
use PHPSecurityScanner;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Tuli\Command;
use Tuli\Rule;

class Scan extends Command {

    /**
     * @var Tuli\Rule[]
     */
    protected $rules = [];

    protected function configure() {
        parent::configure();
        $this->setName('scan')
            ->setDescription('Scan the provided files');
    }

    protected function execute(InputInterface $input, OutputInterface $output) {
        $state = parent::execute($input, $output);
        $this->loadRules();
        $errors = [];
        foreach ($this->rules as $rule) {
            echo "Executing rule: " . $rule->getName() . "\n";
            $errors = array_merge($errors, $rule->execute($state));
        }
        foreach ($errors as $error) {
            $this->emitError($error[0], $error[1]);
        }
    }


    public function loadRules() {
        $this->rules[] = new PHPSecurityScanner\Rule\MySQLQuery;
    }

    protected function emitError($msg, Op $op) {
        echo $msg;
        echo " in ";
        echo $op->getFile() . " on line " . $op->getLine();
        echo "\n";
    }

}