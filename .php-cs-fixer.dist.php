<?php

declare(strict_types=1);

use PhpCsFixer\Config;
use PhpCsFixer\Finder;
use PhpCsFixer\Runner\Parallel\ParallelConfigFactory;

return new Config()
    ->setParallelConfig(ParallelConfigFactory::detect())
    ->setRiskyAllowed(true)
    ->setRules([
        '@PER-CS:risky'                => true,
        'binary_operator_spaces'       => [
            'operators' => ['=>' => 'align', '=' => 'align'],
        ],
        'fully_qualified_strict_types' => [
            'import_symbols' => true,
        ],
        'global_namespace_import'      => [
            'import_classes'   => true,
            'import_constants' => false,
            'import_functions' => false,
        ],
        'no_unused_imports'            => true,
        'ordered_imports'              => [
            'sort_algorithm' => 'alpha',
            'imports_order'  => ['class', 'function', 'const'],
        ],
    ])
    ->setFinder(
        new Finder()
            ->in([
                __DIR__ . '/src',
                __DIR__ . '/tests',
            ])
            ->name('*.php')
            ->exclude('vendor')
            ->ignoreDotFiles(true)
            ->ignoreVCSIgnored(true)
    )
;
