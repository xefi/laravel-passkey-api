<?php

namespace Xefi\LaravelPasskey\Tests\Unit;

use Xefi\LaravelPasskey\Actions\CreateSanctumTokenAction;
use Xefi\LaravelPasskey\Actions\CreateWebSessionAction;
use Xefi\LaravelPasskey\Contracts\PasskeyAuthAction;
use Xefi\LaravelPasskey\Tests\TestCase;

class PasskeyServiceProviderTest extends TestCase
{
    public function test_binds_create_web_session_action_by_default(): void
    {
        // Act
        $action = $this->app->make(PasskeyAuthAction::class);

        // Assert
        $this->assertInstanceOf(CreateWebSessionAction::class, $action);
    }

    public function test_uses_configured_auth_action_class(): void
    {
        // Arrange
        $this->app->bind(PasskeyAuthAction::class, CreateSanctumTokenAction::class);

        // Act
        $action = $this->app->make(PasskeyAuthAction::class);

        // Assert
        $this->assertInstanceOf(CreateSanctumTokenAction::class, $action);
    }
}
