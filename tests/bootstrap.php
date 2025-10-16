<?php

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

// Load test support classes
$fakeClock = __DIR__ . '/Support/FakeClock.php';
if (is_file($fakeClock)) {
    require $fakeClock;
}

// Additional autoloading only for our optional Predis client stub
spl_autoload_register(static function (string $class): void {
    $predis = 'Predis\\';
    if (str_starts_with($class, $predis)) {
        $relative = substr($class, strlen($predis));
        $file = __DIR__ . '/../src/Predis/' . str_replace('\\', '/', $relative) . '.php';
        if (is_file($file)) {
            require $file;
            return;
        }
    }
});
