<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class SeverityLevel extends Model
{
    protected $connection = 'alerts_db';
    protected $table = 'severity_levels';
    public $timestamps = false;

    protected $fillable = ['name', 'level'];

    public function alerts()
    {
        return $this->hasMany(Alert::class, 'severity_id');
    }

    public function rules()
    {
        return $this->hasMany(CorrelationRule::class, 'severity_id');
    }
}
