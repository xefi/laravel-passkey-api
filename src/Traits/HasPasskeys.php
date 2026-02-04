<?php

namespace Thomyris\LaravelPasskey\Traits;

use Illuminate\Database\Eloquent\Relations\HasMany;
use Thomyris\LaravelPasskey\Models\Passkey;

trait HasPasskeys
{
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
