<?php

namespace App\Http\Controllers;

use App\Models\Alert;
use App\Models\RawLog;
use App\Models\CorrelationRule;
use App\Models\User;
use Illuminate\Http\Request;

class DashboardController extends Controller
{
    public function index(Request $request)
    {
        $role = $request->user()->role?->name;

        $alertsTotal  = Alert::count();
        $alertsOpen   = Alert::where('status', 'open')->count();
        $alertsByLevel = Alert::join('severity_levels', 'alerts.severity_id', '=', 'severity_levels.id')
            ->selectRaw('severity_levels.name as severity, count(*) as total')
            ->groupBy('severity_levels.name')
            ->pluck('total', 'severity');

        $recentAlerts = Alert::with('severity', 'rule')
            ->orderByDesc('event_timestamp')
            ->limit(10)
            ->get();

        $data = [
            'alerts_total'    => $alertsTotal,
            'alerts_open'     => $alertsOpen,
            'alerts_by_level' => $alertsByLevel,
            'recent_alerts'   => $recentAlerts,
        ];

        if (in_array($role, ['analyst', 'admin'])) {
            $data['raw_logs_today'] = RawLog::whereDate('created_at', today())->count();
        }

        if ($role === 'admin') {
            $data['total_users']  = User::count();
            $data['active_rules'] = CorrelationRule::where('enabled', true)->count();
        }

        return response()->json($data);
    }
}
