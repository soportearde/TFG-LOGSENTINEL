<?php

namespace App\Policies;

use App\Models\User;

class UserPolicy
{
    public function viewAny(User $user): bool
    {
        return $user->role?->name === 'admin';
    }

    public function view(User $user, User $target): bool
    {
        return $user->role?->name === 'admin' || $user->id === $target->id;
    }

    public function create(User $user): bool
    {
        return $user->role?->name === 'admin';
    }

    public function update(User $user, User $target): bool
    {
        return $user->role?->name === 'admin';
    }

    public function delete(User $user, User $target): bool
    {
        return $user->role?->name === 'admin' && $user->id !== $target->id;
    }
}
