<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class RefreshToken extends Model
{
    protected $fillable = ['user_id', 'token_hash', 'expires_at', 'revoked_at'];

    public function user()
    {
        return $this->belongsTo(User::class);
    }
}

