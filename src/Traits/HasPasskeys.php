<?php

namespace Xefi\LaravelPasskey\Traits;

use Illuminate\Database\Eloquent\Relations\HasMany;
use Xefi\LaravelPasskey\Models\Passkey;

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
