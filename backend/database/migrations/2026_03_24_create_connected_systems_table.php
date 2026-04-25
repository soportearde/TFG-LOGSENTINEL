<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    protected $connection = 'alerts_db';

    public function up(): void
    {
        Schema::connection($this->connection)->create('connected_systems', function (Blueprint $table) {
            $table->id();
            $table->string('system_name', 100);
            $table->string('system_type', 50)->default('ubuntu');
            $table->string('api_key', 64)->unique();
            $table->text('description')->nullable();
            $table->string('ip_address', 45)->nullable();
            $table->string('status', 20)->default('pending');
            $table->timestamp('last_seen')->nullable();
            $table->timestamps();

            $table->index('api_key');
            $table->index('status');
        });
    }

    public function down(): void
    {
        Schema::connection($this->connection)->dropIfExists('connected_systems');
    }
};
