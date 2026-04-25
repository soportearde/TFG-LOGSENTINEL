<?php

namespace App\Http\Controllers;

use App\Models\Report;
use App\Models\Alert;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Storage;

class ReportController extends Controller
{
    public function index(Request $request)
    {
        $reports = $request->user()->role?->name === 'admin'
            ? Report::with('user')->orderByDesc('created_at')->get()
            : $request->user()->reports()->orderByDesc('created_at')->get();

        return response()->json($reports);
    }

    public function store(Request $request)
    {
        $data = $request->validate([
            'title'            => 'required|string|max:255',
            'filters'          => 'nullable|array',
            'filters.status'   => 'nullable|string',
            'filters.severity' => 'nullable|string',
            'filters.from'     => 'nullable|date',
            'filters.to'       => 'nullable|date',
        ]);

        $query = Alert::with('severity', 'rule');
        $filters = $data['filters'] ?? [];

        if (!empty($filters['status']))   $query->where('status', $filters['status']);
        if (!empty($filters['severity'])) $query->whereHas('severity', fn($q) => $q->where('name', $filters['severity']));
        if (!empty($filters['from']))     $query->where('event_timestamp', '>=', $filters['from']);
        if (!empty($filters['to']))       $query->where('event_timestamp', '<=', $filters['to']);

        $alerts = $query->orderByDesc('event_timestamp')->get();

        $filename = 'reports/' . uniqid('report_') . '.csv';
        $rows = ["\xEF\xBB\xBFID,Titulo,Severidad,Regla,Sistema,IP,Usuario,Estado,Fecha,Mensaje"];

        foreach ($alerts as $alert) {
            $rows[] = implode(',', [
                $alert->id,
                '"' . str_replace('"', '""', $alert->title ?? '') . '"',
                '"' . str_replace('"', '""', $alert->severity?->name ?? '') . '"',
                '"' . str_replace('"', '""', $alert->rule?->rule_name ?? '') . '"',
                '"' . str_replace('"', '""', $alert->source_system ?? '') . '"',
                '"' . str_replace('"', '""', $alert->source_ip ?? '') . '"',
                '"' . str_replace('"', '""', $alert->username ?? '') . '"',
                '"' . str_replace('"', '""', $alert->status ?? '') . '"',
                '"' . ($alert->event_timestamp?->format('Y-m-d H:i:s') ?? '') . '"',
                '"' . str_replace('"', '""', $alert->message ?? '') . '"',
            ]);
        }

        Storage::put($filename, implode("\n", $rows));

        $report = $request->user()->reports()->create([
            'title'     => $data['title'],
            'filters'   => $filters,
            'file_path' => $filename,
        ]);

        return response()->json($report, 201);
    }

    public function show(Report $report)
    {
        $this->authorize('view', $report);
        return response()->json($report);
    }

    public function download(Report $report)
    {
        $this->authorize('view', $report);

        if (! Storage::exists($report->file_path)) {
            return response()->json(['message' => 'Archivo no encontrado.'], 404);
        }

        return Storage::download($report->file_path, $report->title . '.csv');
    }

    public function destroy(Report $report)
    {
        $this->authorize('delete', $report);
        Storage::delete($report->file_path);
        $report->delete();
        return response()->json(['message' => 'Informe eliminado.']);
    }
}
