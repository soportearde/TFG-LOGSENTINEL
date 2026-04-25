<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\Hash;
use App\Models\User;
use App\Models\Role;

class UserSeeder extends Seeder
{
    public function run(): void
    {
        $adminRole = Role::where('name', 'admin')->first();

        User::firstOrCreate(
            ['email' => 'admin@logsentinel.com'],
            [
                'name'     => 'Administrador',
                'password' => Hash::make('Admin1234!'),
                'role_id'  => $adminRole->id,
            ]
        );
    }
}
