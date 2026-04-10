<?php

namespace Xefi\LaravelPasskey;

use Illuminate\Support\ServiceProvider;

class PasskeyServiceProvider extends ServiceProvider
{
    /**
     * Register services.
     */
    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__ . '/../config/passkey.php',
            'passkey'
        );

        $this->app->bind(
            \Xefi\LaravelPasskey\Contracts\PasskeyAuthAction::class,
            config('passkey.auth_action', \Xefi\LaravelPasskey\Actions\CreateWebSessionAction::class)
        );
    }

    /**
     * Bootstrap services.
     */
    public function boot(): void
    {
        $this->publishes([
            __DIR__ . '/../config/passkey.php' => config_path('passkey.php'),
        ], 'passkey-config');
        $this->publishes([
            __DIR__ . '/../database/migrations' => database_path('migrations'),
        ], 'passkey-migrations');

        $this->loadMigrationsFrom(__DIR__ . '/../database/migrations');

        $this->loadRoutesFrom(__DIR__ . '/../routes/api.php');
    }
}
