<?php

namespace App\Http\Controllers;

use App\Models\ConnectedSystem;
use App\Models\RawLog;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class RawLogController extends Controller
{
    /**
     * Recibe un evento de log desde el agente instalado en un servidor.
     * Autenticación por X-API-Key (no requiere Sanctum).
     */
    public function store(Request $request)
    {
        $apiKey = $request->header('X-API-Key');

        if (!$apiKey) {
            return response()->json(['error' => 'Falta X-API-Key'], 401);
        }

        $system = ConnectedSystem::where('api_key', $apiKey)->first();

        if (!$system) {
            return response()->json(['error' => 'API key no reconocida'], 401);
        }

        $system->update(['status' => 'active', 'last_seen' => now(), 'ip_address' => $request->ip()]);

        $system->update(['last_seen' => now(), 'ip_address' => $request->ip()]);

        $data = $request->all();

        // El collector persiste los eventos en raw_logs; aqui solo reenviamos el batch
        try {
            Http::timeout(3)->post('http://localhost:5000/log', $data);
        } catch (\Exception $e) {
            Log::warning('Collector no disponible: ' . $e->getMessage());
        }

        return response()->json(['status' => 'ok']);
    }

    public function index(Request $request)
    {
        $query = RawLog::query();

        if ($request->filled('search')) {
            $q = '%' . $request->search . '%';
            $query->where(function ($sub) use ($q) {
                $sub->where('source_system', 'like', $q)
                    ->orWhere('source_ip', 'like', $q)
                    ->orWhere('event_type', 'like', $q)
                    ->orWhere('username', 'like', $q);
            });
        }
        if ($request->filled('source_system')) {
            $query->where('source_system', $request->source_system);
        }
        if ($request->filled('source_ip')) {
            $query->where('source_ip', $request->source_ip);
        }
        if ($request->filled('event_type')) {
            $query->where('event_type', $request->event_type);
        }
        if ($request->filled('from')) {
            $query->where('created_at', '>=', $request->from);
        }
        if ($request->filled('to')) {
            $query->where('created_at', '<=', $request->to);
        }

        return response()->json(
            $query->orderByDesc('created_at')->paginate(100)
        );
    }

    public function show(RawLog $rawLog)
    {
        return response()->json($rawLog);
    }
}
