<?php

namespace Xefi\LaravelPasskey\Tests;

use Xefi\LaravelPasskey\PasskeyServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;

class TestCase extends Orchestra
{
    protected function getPackageProviders($app): array
    {
        return [
            PasskeyServiceProvider::class,
        ];
    }
}
