<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Alert extends Model
{
    protected $connection = 'alerts_db';
    protected $table = 'alerts';
    public $timestamps = false;

    protected $fillable = [
        'rule_id',
        'severity_id',
        'source_ip',
        'username',
        'source_system',
        'title',
        'message',
        'metadata',
        'event_timestamp',
        'status',
    ];

    protected function casts(): array
    {
        return [
            'metadata'        => 'array',
            'event_timestamp' => 'datetime',
        ];
    }

    public function rule()
    {
        return $this->belongsTo(CorrelationRule::class, 'rule_id');
    }

    public function severity()
    {
        return $this->belongsTo(SeverityLevel::class, 'severity_id');
    }
}
