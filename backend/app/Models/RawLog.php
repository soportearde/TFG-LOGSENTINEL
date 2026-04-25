<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class RawLog extends Model
{
    protected $connection = 'log_collector';
    protected $table = 'raw_logs';

    public $timestamps = false;

    protected $fillable = [
        'source_system',
        'source_ip',
        'username',
        'event_type',
        'raw_data',
        'created_at',
    ];

    protected function casts(): array
    {
        return [
            'raw_data'   => 'array',
            'created_at' => 'datetime',
        ];
    }
}
