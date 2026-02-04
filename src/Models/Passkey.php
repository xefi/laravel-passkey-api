<?php

namespace Thomyris\LaravelPasskey\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * Passkey Model
 * 
 * @property int $id
 * @property int $user_id
 * @property string $label
 * @property string $credential_id
 * @property string $challenge
 * @property string $public_key
 * @property \Illuminate\Support\Carbon $created_at
 * @property \Illuminate\Support\Carbon $updated_at
 * 
 * @property-read \Illuminate\Foundation\Auth\User $user
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
        'user_id',
        'credential_id',
        'challenge',
        'public_key',
    ];

    /**
     * Get the user that owns the passkey.
     *
     * @return BelongsTo
     */
    public function user(): BelongsTo
    {
        return $this->belongsTo(config('passkey.user_model', 'App\Models\User'));
    }
}
