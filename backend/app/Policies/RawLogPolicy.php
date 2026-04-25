<?php

namespace App\Policies;

use App\Models\User;
use App\Models\RawLog;

class RawLogPolicy
{
    public function viewAny(User $user): bool
    {
        return true; // todos los usuarios autenticados pueden ver logs (solo lectura para 'user')
    }

    public function view(User $user, RawLog $rawLog): bool
    {
        return true;
    }
}
