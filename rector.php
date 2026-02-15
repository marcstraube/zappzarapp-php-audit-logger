<?php

declare(strict_types=1);

use Rector\Config\RectorConfig;
use Rector\Php84\Rector\MethodCall\NewMethodCallWithoutParenthesesRector;

/** @noinspection PhpUnhandledExceptionInspection - Config files should fail fast on invalid configuration */
return RectorConfig::configure()
    ->withPaths([
        __DIR__ . '/src',
        __DIR__ . '/tests',
    ])
    ->withPhpSets(php84: true)
    ->withPreparedSets(
        deadCode: true,
        codeQuality: true,
        codingStyle: true,
        typeDeclarations: true,
        privatization: true,
        earlyReturn: true
    )
    ->withSkip([
        NewMethodCallWithoutParenthesesRector::class, // pdepend (PHPMD) cannot parse PHP 8.4 new-without-parentheses syntax
    ]);
