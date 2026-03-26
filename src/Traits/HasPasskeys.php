<?php

namespace Xefi\LaravelPasskey\Traits;

use Illuminate\Database\Eloquent\Relations\MorphMany;
use Xefi\LaravelPasskey\Models\Passkey;

trait HasPasskeys
{
    /**
     * The "booting" method of the trait.
     *
     * @return void
     */
    protected static function bootHasPasskeys(): void
    {
        static::deleting(function ($model) {
            $model->passkeys()->delete();
        });
    }

    /**
     * Get all of the model's passkeys.
     *
     * @return MorphMany
     */
    public function passkeys(): MorphMany
    {
        return $this->morphMany(Passkey::class, 'passkeeable');
    }

    /**
     * Get the display name to use for passkey registration.
     * Override in your model to use a different field (e.g. username, display_name).
     *
     * @return string
     */
    public function getPasskeyDisplayName(): string
    {
        return $this->name ?? $this->email ?? (string) $this->getKey();
    }

    /**
     * Get the email to use for passkey registration.
     * Override in your model if the email field has a different name.
     *
     * @return string
     */
    public function getPasskeyEmail(): string
    {
        return $this->email ?? '';
    }
}
