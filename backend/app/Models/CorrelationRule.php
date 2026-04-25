<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class CorrelationRule extends Model
{
    protected $connection = 'alerts_db';
    protected $table = 'correlation_rules';
    public $timestamps = false;

    protected $fillable = [
        'rule_name',
        'description',
        'severity_id',
        'enabled',
        'conditions',
    ];

    protected function casts(): array
    {
        return [
            'enabled'    => 'boolean',
            'conditions' => 'array',
        ];
    }

    public function alerts()
    {
        return $this->hasMany(Alert::class, 'rule_id');
    }

    public function severity()
    {
        return $this->belongsTo(SeverityLevel::class, 'severity_id');
    }
}
