<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;

class ConnectedSystem extends Model
{
    // Usamos la misma conexión que las alertas
    protected $connection = 'alerts_db';
    protected $table = 'connected_systems';
    public $timestamps = false;

    protected $fillable = [
        'system_name',
        'system_type',
        'api_key',
        'description',
        'ip_address',
        'status',
        'last_seen',
    ];

    protected function casts(): array
    {
        return [
            'last_seen' => 'datetime',
        ];
    }

    /**
     * Genera una API key única al crear un sistema nuevo.
     */
    public static function generateApiKey(): string
    {
        return bin2hex(random_bytes(32));
    }

    /**
     * Genera el comando de instalación para este sistema.
     */
   public function getInstallCommand(string $baseUrl): string
    {
        $logUrl = rtrim($baseUrl, '/') . '/api/log';
        $agentUrl = rtrim($baseUrl, '/');

        return "curl -sSL {$agentUrl}/agent/install.sh | sudo bash -s -- "
             . "--url {$logUrl} "
             . "--api-key {$this->api_key} "
             . "--name \"{$this->system_name}\"";
    }
}
