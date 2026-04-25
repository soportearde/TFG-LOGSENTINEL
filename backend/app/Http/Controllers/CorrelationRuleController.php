<?php

namespace App\Http\Controllers;

use App\Models\CorrelationRule;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class CorrelationRuleController extends Controller
{
    // URL interna del correlador Flask
    private const CORRELATOR = 'http://localhost:7000';

    public function index()
    {
        return response()->json(
            CorrelationRule::with('severity')->orderBy('rule_name')->get()
        );
    }

    public function store(Request $request)
    {
        $data = $request->validate([
            'rule_name'   => 'required|string|unique:alerts_db.correlation_rules,rule_name',
            'description' => 'nullable|string',
            'severity_id' => 'required|integer',
            'enabled'     => 'boolean',
            'conditions'  => 'nullable|array',
        ]);

        // Guardar en BD
        $rule = CorrelationRule::create($data);

        // Generar el código Python de la regla y activarla en el correlador
        if (!empty($data['description'])) {
            try {
                $response = Http::timeout(60)->post(self::CORRELATOR . '/api/rules/generate', [
                    'rule_name'   => $data['rule_name'],
                    'description' => $data['description'],
                ]);

                if (!$response->successful()) {
                    Log::warning('Correlator generate failed', [
                        'rule'   => $data['rule_name'],
                        'status' => $response->status(),
                        'body'   => $response->body(),
                    ]);
                }
            } catch (\Exception $e) {
                Log::error('Error llamando al correlador: ' . $e->getMessage());
            }
        }

        return response()->json($rule->load('severity'), 201);
    }

    public function show(CorrelationRule $correlationRule)
    {
        return response()->json($correlationRule->load('severity'));
    }

    public function update(Request $request, CorrelationRule $correlationRule)
    {
        $data = $request->validate([
            'rule_name'   => 'sometimes|string|unique:alerts_db.correlation_rules,rule_name,' . $correlationRule->id,
            'description' => 'nullable|string',
            'severity_id' => 'sometimes|integer',
            'enabled'     => 'boolean',
            'conditions'  => 'nullable|array',
        ]);

        $correlationRule->update($data);

        // Sincronizar estado enabled/disabled con el correlador
        if (array_key_exists('enabled', $data)) {
            try {
                Http::timeout(10)->post(self::CORRELATOR . '/api/rules/toggle', [
                    'rule_name' => $correlationRule->rule_name,
                    'enabled'   => $data['enabled'],
                ]);
            } catch (\Exception $e) {
                Log::error('Error toggleando regla en correlador: ' . $e->getMessage());
            }
        }

        return response()->json($correlationRule->fresh()->load('severity'));
    }

    public function code(CorrelationRule $correlationRule)
    {
        try {
            $response = Http::timeout(5)->get(
                self::CORRELATOR . '/api/rules/' . urlencode($correlationRule->rule_name) . '/code'
            );

            if ($response->successful()) {
                return response()->json(['code' => $response->json('code')]);
            }

            return response()->json(['code' => null]);
        } catch (\Exception $e) {
            return response()->json(['code' => null]);
        }
    }

    public function destroy(CorrelationRule $correlationRule)
    {
        // Desvinculamos las alertas que referencian esta regla antes de borrarla
        // para evitar el error de foreign key constraint
        $correlationRule->alerts()->update(['rule_id' => null]);

        $correlationRule->delete();

        // Recargar reglas en el correlador para que deje de procesar la eliminada
        try {
            Http::timeout(10)->post(self::CORRELATOR . '/api/rules/reload');
        } catch (\Exception $e) {
            Log::error('Error recargando reglas tras borrado: ' . $e->getMessage());
        }

        return response()->json(['message' => 'Regla eliminada.']);
    }
}
