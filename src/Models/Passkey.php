<?php

namespace Xefi\LaravelPasskey\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphTo;

/**
 * Passkey Model
 *
 * @property int $id
 * @property int $passkeeable_id
 * @property string $passkeeable_type
 * @property string $label
 * @property string $credential_id
 * @property string $challenge
 * @property string $public_key
 * @property \Illuminate\Support\Carbon $created_at
 * @property \Illuminate\Support\Carbon $updated_at
 *
 * @property-read \Illuminate\Database\Eloquent\Model $passkeeable
 */
class Passkey extends Model
{
    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'label',
        'passkeeable_id',
        'passkeeable_type',
        'credential_id',
        'challenge',
        'public_key',
    ];

    /**
     * Get the owning passkeeable model (User, Admin, Client, etc.).
     *
     * Any model using the HasPasskeys trait can own passkeys via this
     * polymorphic relationship.
     *
     * @return MorphTo
     */
    public function passkeeable(): MorphTo
    {
        return $this->morphTo();
    }
}
