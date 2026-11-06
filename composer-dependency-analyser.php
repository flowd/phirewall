<?php

declare(strict_types=1);

use ShipMonk\ComposerDependencyAnalyser\Config\Configuration;
use ShipMonk\ComposerDependencyAnalyser\Config\ErrorType;

// Baseline of the findings that existed when the monorepo was set up. New undeclared
// dependencies still fail the check. Declare an entry in composer.json and remove it
// here once it is fixed.
return (new Configuration())
    ->ignoreErrorsOnExtension('ext-ctype', [ErrorType::SHADOW_DEPENDENCY])
    ->ignoreErrorsOnExtension('ext-filter', [ErrorType::SHADOW_DEPENDENCY])
    ->ignoreErrorsOnExtension('ext-pdo', [ErrorType::SHADOW_DEPENDENCY])
    ->ignoreErrorsOnExtension('ext-zend-opcache', [ErrorType::SHADOW_DEPENDENCY])
    // Optional integrations, listed under "suggest" (predis/predis, ext-apcu). With ext-apcu
    // loaded (CI runners) APCUIterator is a shadow dependency, without it an unknown class.
    ->ignoreErrorsOnExtension('ext-apcu', [ErrorType::SHADOW_DEPENDENCY])
    ->ignoreUnknownClasses(['APCUIterator', 'Predis\Client', 'Predis\ClientInterface'])
    // Which of the two applies depends on the loaded extensions of the machine.
    ->disableReportingUnmatchedIgnores()
    ;
