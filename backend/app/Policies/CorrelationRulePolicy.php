<?php

namespace App\Policies;

use App\Models\User;
use App\Models\CorrelationRule;

class CorrelationRulePolicy
{
    public function viewAny(User $user): bool
    {
        return $user->role?->name === 'admin';
    }

    public function view(User $user, CorrelationRule $rule): bool
    {
        return $user->role?->name === 'admin';
    }

    public function create(User $user): bool
    {
        return $user->role?->name === 'admin';
    }

    public function update(User $user, CorrelationRule $rule): bool
    {
        return $user->role?->name === 'admin';
    }

    public function delete(User $user, CorrelationRule $rule): bool
    {
        return $user->role?->name === 'admin';
    }
}
