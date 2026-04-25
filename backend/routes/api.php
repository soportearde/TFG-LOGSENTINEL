<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\DashboardController;
use App\Http\Controllers\AlertController;
use App\Http\Controllers\RawLogController;
use App\Http\Controllers\CorrelationRuleController;
use App\Http\Controllers\UserController;
use App\Http\Controllers\ReportController;
use App\Http\Controllers\ConnectedSystemController;

// ── Auth (público) ─────────────────────────────────────────────
Route::post('/login', [AuthController::class, 'login']);

// ── Endpoints del agente (públicos, se autentican por API key) ──
Route::post('/systems/heartbeat', [ConnectedSystemController::class, 'heartbeat']);
Route::post('/log', [RawLogController::class, 'store']);

// ── Descarga del plugin (pública, no necesita Sanctum) ─────────
Route::get('connected-systems/{connected_system}/download-plugin',
    [ConnectedSystemController::class, 'downloadPlugin']);

// ── Rutas protegidas ───────────────────────────────────────────
Route::middleware('auth:sanctum')->group(function () {

    // Auth
    Route::post('/logout', [AuthController::class, 'logout']);
    Route::get('/me',      [AuthController::class, 'me']);

    // Dashboard
    Route::get('/dashboard', [DashboardController::class, 'index']);

    // Alertas (analyst + admin)
    Route::middleware('can:viewAny,App\Models\Alert')->group(function () {
        Route::get('/alerts',                  [AlertController::class, 'index']);
        Route::get('/alerts/{alert}',          [AlertController::class, 'show']);
        Route::patch('/alerts/{alert}/status', [AlertController::class, 'updateStatus']);
        Route::delete('/alerts/{alert}',       [AlertController::class, 'destroy']);
    });

    // Logs en bruto (analyst + admin)
    Route::middleware('can:viewAny,App\Models\RawLog')->group(function () {
        Route::get('/raw-logs',           [RawLogController::class, 'index']);
        Route::get('/raw-logs/{rawLog}',  [RawLogController::class, 'show']);
    });

    // Informes (analyst + admin)
    Route::middleware('can:viewAny,App\Models\Report')->group(function () {
        Route::get('/reports',                    [ReportController::class, 'index']);
        Route::post('/reports',                   [ReportController::class, 'store']);
        Route::get('/reports/{report}',           [ReportController::class, 'show']);
        Route::get('/reports/{report}/download',  [ReportController::class, 'download']);
        Route::delete('/reports/{report}',        [ReportController::class, 'destroy']);
    });

    // Reglas de correlación (solo admin)
    Route::middleware('can:viewAny,App\Models\CorrelationRule')->group(function () {
        Route::get('correlation-rules/{correlationRule}/code', [CorrelationRuleController::class, 'code']);
        Route::apiResource('correlation-rules', CorrelationRuleController::class);
    });

    // Usuarios (solo admin)
    Route::middleware('can:viewAny,App\Models\User')->group(function () {
        Route::get('/roles', [UserController::class, 'roles']);
        Route::patch('/users/{user}/toggle-active', [UserController::class, 'toggleActive']);
        Route::apiResource('users', UserController::class);
    });

    // Sistemas conectados (solo admin)
    Route::middleware('can:viewAny,App\Models\User')->group(function () {
        Route::apiResource('connected-systems', ConnectedSystemController::class);
        Route::get('connected-systems/{connected_system}/install-command',
            [ConnectedSystemController::class, 'installCommand']);
        Route::post('connected-systems/{connected_system}/regenerate-key',
            [ConnectedSystemController::class, 'regenerateKey']);
    });
});
