<?php

namespace App\Http\Controllers;

use App\Models\Alert;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;

class AlertController extends Controller
{
    public function index(Request $request)
    {
        $query = Alert::with('severity', 'rule');

        if ($request->filled('status')) {
            $query->where('status', $request->status);
        }
        if ($request->filled('severity')) {
            $query->whereHas('severity', fn($q) => $q->where('name', $request->severity));
        }
        if ($request->filled('search')) {
            $q = '%' . $request->search . '%';
            $query->where(function ($sub) use ($q) {
                $sub->where('title', 'like', $q)
                    ->orWhere('source_system', 'like', $q)
                    ->orWhere('source_ip', 'like', $q)
                    ->orWhere('username', 'like', $q);
            });
        }
        if ($request->filled('source_system')) {
            $query->where('source_system', $request->source_system);
        }
        if ($request->filled('from')) {
            $query->where('event_timestamp', '>=', $request->from);
        }
        if ($request->filled('to')) {
            $query->where('event_timestamp', '<=', $request->to);
        }

        return response()->json(
            $query->orderByDesc('event_timestamp')->paginate(50)
        );
    }

    public function show(Alert $alert)
    {
        return response()->json($alert->load('severity', 'rule'));
    }

    public function destroy(Alert $alert)
    {
        Gate::authorize('delete', $alert);
        $alert->delete();
        return response()->json(['message' => 'Alerta eliminada.']);
    }

    public function updateStatus(Request $request, Alert $alert)
    {
        $request->validate([
            'status' => 'required|in:open,in_progress,resolved,dismissed',
        ]);

        $alert->update(['status' => $request->status]);

        return response()->json($alert->load('severity', 'rule'));
    }
}
