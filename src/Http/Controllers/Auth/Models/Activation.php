<?php

namespace Karla\Http\Controllers\Auth\Models;

use Karla\User;
use Illuminate\Database\Eloquent\Model;

class Activation extends Model
{
    protected $table = "auth_activations";

    public function user()
    {
        return $this->belongsTo(User::class);
    }
}
