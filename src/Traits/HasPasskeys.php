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
}
