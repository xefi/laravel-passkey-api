<?php

namespace Xefi\LaravelPasskey\Traits;

use Illuminate\Database\Eloquent\Relations\HasMany;
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
        static::deleting(function ($user) {
            $user->passkeys()->delete();
        });
    }

    /**
     * Get all of the user's passkeys.
     *
     * @return HasMany
     */
    public function passkeys(): HasMany
    {
        return $this->hasMany(Passkey::class, 'user_id');
    }
}
