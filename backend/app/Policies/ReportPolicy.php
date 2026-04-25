<?php

namespace App\Policies;

use App\Models\User;
use App\Models\Report;

class ReportPolicy
{
    public function viewAny(User $user): bool
    {
        return in_array($user->role?->name, ['analyst', 'admin']);
    }

    public function view(User $user, Report $report): bool
    {
        return $user->role?->name === 'admin' || $user->id === $report->user_id;
    }

    public function create(User $user): bool
    {
        return in_array($user->role?->name, ['analyst', 'admin']);
    }

    public function delete(User $user, Report $report): bool
    {
        return $user->role?->name === 'admin' || $user->id === $report->user_id;
    }
}
