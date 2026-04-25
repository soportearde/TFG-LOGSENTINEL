<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Report extends Model
{
    protected $connection = 'pgsql';

    protected $fillable = [
        'user_id',
        'title',
        'filters',
        'file_path',
    ];

    protected function casts(): array
    {
        return [
            'filters' => 'array',
        ];
    }

    public function user()
    {
        return $this->belongsTo(User::class);
    }
}
