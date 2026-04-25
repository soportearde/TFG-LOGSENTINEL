<?php

namespace App\Providers;

use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Facades\Gate;
use App\Models\Alert;
use App\Models\RawLog;
use App\Models\CorrelationRule;
use App\Models\User;
use App\Models\Report;
use App\Policies\AlertPolicy;
use App\Policies\RawLogPolicy;
use App\Policies\CorrelationRulePolicy;
use App\Policies\UserPolicy;
use App\Policies\ReportPolicy;

class AppServiceProvider extends ServiceProvider
{
    public function register(): void {}

    public function boot(): void
    {
        Gate::policy(Alert::class,           AlertPolicy::class);
        Gate::policy(RawLog::class,          RawLogPolicy::class);
        Gate::policy(CorrelationRule::class, CorrelationRulePolicy::class);
        Gate::policy(User::class,            UserPolicy::class);
        Gate::policy(Report::class,          ReportPolicy::class);
    }
}
