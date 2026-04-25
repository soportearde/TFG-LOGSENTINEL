# LogSentinel — Documentación Completa del Backend (Laravel)

> **Proyecto:** LogSentinel — Sistema SIEM de monitorización y correlación de eventos de seguridad
> **Stack:** Laravel 11 · PHP 8.3 · PostgreSQL 16 · Laravel Sanctum
> **Servidor:** 20.238.17.71 (Azure VM)
> **API base URL:** `http://localhost:8000/api`

---

## Índice

1. [Arquitectura de bases de datos](#1-arquitectura-de-bases-de-datos)
2. [Migraciones](#2-migraciones)
3. [Modelos](#3-modelos)
4. [Seeders](#4-seeders)
5. [Controladores](#5-controladores)
6. [Policies (Autorización)](#6-policies-autorización)
7. [Rutas API](#7-rutas-api)
8. [Pruebas documentadas](#8-pruebas-documentadas)

---

## 1. Arquitectura de bases de datos

LogSentinel utiliza **tres bases de datos PostgreSQL independientes**, cada una con una responsabilidad clara:

```
┌─────────────────────────────────────────────────────────┐
│                    PostgreSQL Server                     │
│                    20.238.17.71:5432                    │
│                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │ logsentinel  │  │  alerts_db   │  │log_collector │  │
│  │              │  │              │  │              │  │
│  │ users        │  │ alerts       │  │ raw_logs     │  │
│  │ roles        │  │ corr_rules   │  │              │  │
│  │ reports      │  │ severity_lvl │  │              │  │
│  │ sessions     │  │              │  │              │  │
│  │ migrations   │  │              │  │              │  │
│  │              │  │              │  │              │  │
│  │ ← Laravel    │  │ ← Python +   │  │ ← Python     │  │
│  │   gestiona   │  │   Laravel    │  │   escribe    │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  │
└─────────────────────────────────────────────────────────┘
```

| Base de datos | Quién escribe | Quién lee | Descripción |
|---|---|---|---|
| `logsentinel` | Laravel | Laravel | Usuarios, roles, sesiones, informes de la plataforma |
| `alerts_db` | Python (correlator) + Laravel | Laravel | Alertas generadas, reglas de correlación, niveles de severidad |
| `log_collector` | Python (logcollector) | Laravel | Logs en bruto recibidos de los sistemas monitorizados |

La conexión entre bases de datos está definida en `config/database.php` mediante tres conexiones nombradas: `pgsql`, `alerts_db` y `log_collector`.

---

## 2. Migraciones

Las migraciones son archivos PHP que definen la estructura de las tablas de la base de datos `logsentinel` (la propia de Laravel). Las bases de datos `alerts_db` y `log_collector` son creadas y gestionadas por los servicios Python, por lo que Laravel **no las migra**.

### 2.1 — Migración: roles, users, sessions, password_reset_tokens

**Archivo:** `database/migrations/0001_01_01_000000_create_users_table.php`

Esta migración crea cuatro tablas en orden lógico: primero `roles` (porque `users` depende de ella), luego `users`, y finalmente las tablas auxiliares de sesiones y recuperación de contraseña.

```php
<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // Tabla de roles: define los perfiles de acceso
        Schema::create('roles', function (Blueprint $table) {
            $table->id();
            $table->string('name')->unique(); // admin, analyst, user
            $table->timestamps();
        });

        // Tabla de usuarios: vinculada a roles mediante FK
        Schema::create('users', function (Blueprint $table) {
            $table->id();
            $table->string('name');
            $table->string('email')->unique();
            $table->timestamp('email_verified_at')->nullable();
            $table->string('password');
            $table->foreignId('role_id')->nullable()->constrained('roles')->nullOnDelete();
            $table->rememberToken();
            $table->timestamps();
        });

        // Tabla de tokens para recuperación de contraseña
        Schema::create('password_reset_tokens', function (Blueprint $table) {
            $table->string('email')->primary();
            $table->string('token');
            $table->timestamp('created_at')->nullable();
        });

        // Tabla de sesiones (usada por Laravel para gestionar sesiones de usuario)
        Schema::create('sessions', function (Blueprint $table) {
            $table->string('id')->primary();
            $table->foreignId('user_id')->nullable()->index();
            $table->string('ip_address', 45)->nullable();
            $table->text('user_agent')->nullable();
            $table->longText('payload');
            $table->integer('last_activity')->index();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('sessions');
        Schema::dropIfExists('password_reset_tokens');
        Schema::dropIfExists('users');
        Schema::dropIfExists('roles');
    }
};
```

**Columnas de `roles`:**

| Columna | Tipo | Descripción |
|---|---|---|
| `id` | BIGINT PK | Identificador único autoincremental |
| `name` | VARCHAR UNIQUE | Nombre del rol: `admin`, `analyst`, `user` |
| `created_at` | TIMESTAMP | Fecha de creación |
| `updated_at` | TIMESTAMP | Fecha de última modificación |

**Columnas de `users`:**

| Columna | Tipo | Descripción |
|---|---|---|
| `id` | BIGINT PK | Identificador único autoincremental |
| `name` | VARCHAR | Nombre del usuario |
| `email` | VARCHAR UNIQUE | Correo electrónico (usado para login) |
| `email_verified_at` | TIMESTAMP NULL | Fecha de verificación del email |
| `password` | VARCHAR | Contraseña hasheada con bcrypt |
| `role_id` | BIGINT FK NULL | Referencia a `roles.id`. Si se borra el rol, pasa a NULL |
| `remember_token` | VARCHAR NULL | Token de sesión persistente |
| `created_at` | TIMESTAMP | Fecha de creación |
| `updated_at` | TIMESTAMP | Fecha de última modificación |

---

### 2.2 — Migración: cache, jobs

**Archivos:**
- `database/migrations/0001_01_01_000001_create_cache_table.php`
- `database/migrations/0001_01_01_000002_create_jobs_table.php`

Migraciones generadas automáticamente por Laravel. La tabla `cache` almacena el caché de la aplicación y `jobs` gestiona las colas de trabajos asíncronos. No requieren modificaciones para este proyecto.

---

### 2.3 — Migración: reports

**Archivo:** `database/migrations/0001_01_01_000003_create_reports_table.php`

Crea la tabla de informes generados por analistas y administradores. Cada informe pertenece a un usuario y contiene los filtros usados para generarlo y la ruta al archivo CSV resultante.

```php
<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('reports', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->constrained('users')->cascadeOnDelete();
            $table->string('title');
            $table->json('filters')->nullable();
            $table->string('file_path')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('reports');
    }
};
```

**Columnas de `reports`:**

| Columna | Tipo | Descripción |
|---|---|---|
| `id` | BIGINT PK | Identificador único autoincremental |
| `user_id` | BIGINT FK | Referencia a `users.id`. Se elimina en cascada si se borra el usuario |
| `title` | VARCHAR | Título descriptivo del informe |
| `filters` | JSON NULL | Filtros aplicados al generar el informe (status, severity, rango de fechas) |
| `file_path` | VARCHAR NULL | Ruta al archivo CSV generado en el almacenamiento local |
| `created_at` | TIMESTAMP | Fecha de creación |
| `updated_at` | TIMESTAMP | Fecha de última modificación |

---

### 2.4 — Migración: personal_access_tokens (Sanctum)

**Archivo:** `database/migrations/2026_03_16_175242_create_personal_access_tokens_table.php`

Generada automáticamente al instalar **Laravel Sanctum** (`php artisan install:api`). Almacena los tokens de autenticación de la API. Cada token está vinculado a un modelo (en este caso `User`) y puede tener capacidades específicas, fecha de expiración y registro del último uso.

```php
<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('personal_access_tokens', function (Blueprint $table) {
            $table->id();
            $table->morphs('tokenable');        // tokenable_type + tokenable_id
            $table->text('name');               // nombre del token (ej: 'api-token')
            $table->string('token', 64)->unique(); // hash del token
            $table->text('abilities')->nullable();  // permisos del token
            $table->timestamp('last_used_at')->nullable();
            $table->timestamp('expires_at')->nullable()->index();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('personal_access_tokens');
    }
};
```

---

## 3. Modelos

Los modelos son las clases PHP que representan las tablas de la base de datos y encapsulan la lógica de acceso a datos. Laravel utiliza **Eloquent ORM** para mapear las filas de las tablas a objetos PHP.

Cada modelo declara explícitamente su conexión mediante `$connection` para que Laravel sepa a qué base de datos dirigir las consultas.

---

### 3.1 — Modelo User

**Archivo:** `app/Models/User.php`
**Tabla:** `users` · **Conexión:** `pgsql` (logsentinel)

Representa a los usuarios de la plataforma. Extiende `Authenticatable` para integración con el sistema de autenticación de Laravel. Incluye el trait `HasApiTokens` de Sanctum para la generación de tokens de API.

```php
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Sanctum\HasApiTokens;

class User extends Authenticatable
{
    use HasApiTokens, HasFactory, Notifiable;

    protected $connection = 'pgsql';

    protected $fillable = [
        'name',
        'email',
        'password',
        'role_id',
    ];

    protected $hidden = [
        'password',
        'remember_token',
    ];

    protected function casts(): array
    {
        return [
            'email_verified_at' => 'datetime',
            'password'          => 'hashed',   // bcrypt automático al asignar
        ];
    }

    // Un usuario pertenece a un rol
    public function role()
    {
        return $this->belongsTo(Role::class);
    }

    // Un usuario puede tener muchos informes
    public function reports()
    {
        return $this->hasMany(Report::class);
    }
}
```

**Relaciones:**
- `role()` → `BelongsTo(Role)` — Un usuario tiene un rol asignado
- `reports()` → `HasMany(Report)` — Un usuario puede haber generado múltiples informes

---

### 3.2 — Modelo Role

**Archivo:** `app/Models/Role.php`
**Tabla:** `roles` · **Conexión:** `pgsql` (logsentinel)

Representa los roles de acceso de la plataforma. Los tres roles disponibles son: `admin`, `analyst` y `user`.

```php
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Role extends Model
{
    protected $connection = 'pgsql';

    protected $fillable = ['name'];

    // Un rol puede tener muchos usuarios
    public function users()
    {
        return $this->hasMany(User::class);
    }
}
```

**Roles del sistema:**

| Nombre | Descripción |
|---|---|
| `admin` | Acceso total: gestiona usuarios, reglas, ve alertas, genera informes |
| `analyst` | Ve alertas, logs en bruto, cambia estado de alertas, genera informes |
| `user` | Solo puede ver sus propios datos de sesión |

---

### 3.3 — Modelo Report

**Archivo:** `app/Models/Report.php`
**Tabla:** `reports` · **Conexión:** `pgsql` (logsentinel)

Representa los informes generados en formato CSV. Los filtros se almacenan como JSON y se deserializan automáticamente como array PHP gracias al cast.

```php
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
            'filters' => 'array',  // JSON ↔ array PHP automático
        ];
    }

    // Un informe pertenece a un usuario
    public function user()
    {
        return $this->belongsTo(User::class);
    }
}
```

---

### 3.4 — Modelo Alert

**Archivo:** `app/Models/Alert.php`
**Tabla:** `alerts` · **Conexión:** `alerts_db`

Representa las alertas de seguridad generadas por el motor de correlación Python. Laravel solo lee de esta tabla (excepto para cambios de estado). Los campos `metadata` y `event_timestamp` tienen casts automáticos.

```php
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Alert extends Model
{
    protected $connection = 'alerts_db';
    protected $table = 'alerts';

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
            'metadata'        => 'array',    // JSONB ↔ array PHP
            'event_timestamp' => 'datetime', // timestamp ↔ Carbon
        ];
    }

    // Una alerta está generada por una regla de correlación
    public function rule()
    {
        return $this->belongsTo(CorrelationRule::class, 'rule_id');
    }

    // Una alerta tiene un nivel de severidad
    public function severity()
    {
        return $this->belongsTo(SeverityLevel::class, 'severity_id');
    }
}
```

**Estados posibles de una alerta (`status`):**

| Estado | Descripción |
|---|---|
| `open` | Alerta nueva, sin tratar |
| `in_progress` | Un analista la está investigando |
| `resolved` | Alerta resuelta |
| `dismissed` | Descartada como falso positivo |

---

### 3.5 — Modelo CorrelationRule

**Archivo:** `app/Models/CorrelationRule.php`
**Tabla:** `correlation_rules` · **Conexión:** `alerts_db`

Representa las reglas de correlación que el motor Python evalúa para generar alertas. Los administradores pueden activar/desactivar reglas desde el panel web.

```php
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class CorrelationRule extends Model
{
    protected $connection = 'alerts_db';
    protected $table = 'correlation_rules';

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
            'enabled'    => 'boolean', // true/false automático
            'conditions' => 'array',   // JSON ↔ array PHP
        ];
    }

    // Una regla puede haber generado muchas alertas
    public function alerts()
    {
        return $this->hasMany(Alert::class, 'rule_id');
    }

    // Una regla tiene un nivel de severidad por defecto
    public function severity()
    {
        return $this->belongsTo(SeverityLevel::class, 'severity_id');
    }
}
```

**Reglas de correlación activas en el sistema:**

| rule_name | Descripción |
|---|---|
| `failed_login_bruteforce` | Más de 5 fallos de login en 180 segundos |
| `login_sequence` | Fallo de login seguido de éxito en menos de 60 segundos |
| `blacklist_ip` | Acceso desde una IP en lista negra |
| `geoip_restriction` | Acceso desde un país no permitido |
| `dos_detection` | Más de 20 peticiones en 10 segundos desde la misma IP |
| `tor_exit_node` | Conexión detectada desde un nodo de salida TOR |

---

### 3.6 — Modelo SeverityLevel

**Archivo:** `app/Models/SeverityLevel.php`
**Tabla:** `severity_levels` · **Conexión:** `alerts_db`

Representa los niveles de severidad de alertas y reglas. La tabla está en `alerts_db` y fue creada manualmente (no por migración de Laravel) ya que la gestiona el ecosistema Python.

```php
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class SeverityLevel extends Model
{
    protected $connection = 'alerts_db';
    protected $table = 'severity_levels';

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
```

**Niveles de severidad:**

| id | name | level | Descripción |
|---|---|---|---|
| 1 | `low` | 1 | Severidad baja, informativo |
| 2 | `medium` | 2 | Severidad media, requiere revisión |
| 3 | `high` | 3 | Severidad alta, requiere atención pronta |
| 4 | `critical` | 4 | Crítico, requiere acción inmediata |

---

### 3.7 — Modelo RawLog

**Archivo:** `app/Models/RawLog.php`
**Tabla:** `raw_logs` · **Conexión:** `log_collector`

Representa los logs en bruto recibidos por el logcollector Python antes de ser normalizados. Laravel tiene acceso de **solo lectura** a esta tabla. Se declara `$timestamps = false` porque la tabla solo tiene `created_at`, no `updated_at`.

```php
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class RawLog extends Model
{
    protected $connection = 'log_collector';
    protected $table = 'raw_logs';

    public $timestamps = false; // solo tiene created_at, no updated_at

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
            'raw_data'   => 'array',    // JSONB ↔ array PHP
            'created_at' => 'datetime',
        ];
    }
}
```

---

## 4. Seeders

Los seeders insertan datos iniciales en la base de datos de forma automática mediante el comando `php artisan db:seed`.

### 4.1 — RoleSeeder

**Archivo:** `database/seeders/RoleSeeder.php`

Crea los tres roles del sistema si no existen. Utiliza `firstOrCreate` para ser idempotente (se puede ejecutar varias veces sin duplicar datos).

```php
<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use App\Models\Role;

class RoleSeeder extends Seeder
{
    public function run(): void
    {
        foreach (['admin', 'analyst', 'user'] as $name) {
            Role::firstOrCreate(['name' => $name]);
        }
    }
}
```

### 4.2 — UserSeeder

**Archivo:** `database/seeders/UserSeeder.php`

Crea el usuario administrador por defecto. La contraseña se hashea automáticamente gracias al cast `'password' => 'hashed'` del modelo User.

```php
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
```

**Usuario administrador creado:**
- **Email:** `admin@logsentinel.com`
- **Password:** `Admin1234!`
- **Rol:** `admin`

### 4.3 — DatabaseSeeder

**Archivo:** `database/seeders/DatabaseSeeder.php`

Orquesta la ejecución de todos los seeders en el orden correcto (roles antes que usuarios).

```php
<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;

class DatabaseSeeder extends Seeder
{
    public function run(): void
    {
        $this->call([
            RoleSeeder::class,
            UserSeeder::class,
        ]);
    }
}
```

---

## 5. Controladores

Los controladores gestionan las peticiones HTTP de la API, aplican validaciones, invocan los modelos y devuelven respuestas JSON. Todos los controladores devuelven respuestas con `response()->json()`.

---

### 5.1 — AuthController

**Archivo:** `app/Http/Controllers/AuthController.php`
**Acceso:** Público (`login`) · Autenticado (`logout`, `me`)

Gestiona la autenticación de la API mediante tokens Sanctum. El flujo es: el cliente envía credenciales → recibe un token → usa ese token en el header `Authorization: Bearer {token}` en todas las demás peticiones.

```php
<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;

class AuthController extends Controller
{
    // POST /api/login — Genera un token de acceso
    public function login(Request $request)
    {
        $request->validate([
            'email'    => 'required|email',
            'password' => 'required|string',
        ]);

        $user = User::where('email', $request->email)->with('role')->first();

        if (! $user || ! Hash::check($request->password, $user->password)) {
            throw ValidationException::withMessages([
                'email' => ['Credenciales incorrectas.'],
            ]);
        }

        $token = $user->createToken('api-token')->plainTextToken;

        return response()->json([
            'token' => $token,
            'user'  => [
                'id'    => $user->id,
                'name'  => $user->name,
                'email' => $user->email,
                'role'  => $user->role?->name,
            ],
        ]);
    }

    // POST /api/logout — Invalida el token actual
    public function logout(Request $request)
    {
        $request->user()->currentAccessToken()->delete();

        return response()->json(['message' => 'Sesión cerrada.']);
    }

    // GET /api/me — Devuelve los datos del usuario autenticado
    public function me(Request $request)
    {
        $user = $request->user()->load('role');

        return response()->json([
            'id'    => $user->id,
            'name'  => $user->name,
            'email' => $user->email,
            'role'  => $user->role?->name,
        ]);
    }
}
```

---

### 5.2 — DashboardController

**Archivo:** `app/Http/Controllers/DashboardController.php`
**Acceso:** Todos los roles autenticados

Devuelve estadísticas de la plataforma adaptadas al rol del usuario. Un usuario básico ve las estadísticas generales; analistas ven además el conteo de logs del día; administradores ven adicionalmente el total de usuarios y reglas activas.

```php
<?php

namespace App\Http\Controllers;

use App\Models\Alert;
use App\Models\RawLog;
use App\Models\CorrelationRule;
use App\Models\User;
use Illuminate\Http\Request;

class DashboardController extends Controller
{
    // GET /api/dashboard
    public function index(Request $request)
    {
        $role = $request->user()->role?->name;

        // Estadísticas comunes a todos los roles
        $alertsTotal   = Alert::count();
        $alertsOpen    = Alert::where('status', 'open')->count();
        $alertsByLevel = Alert::join('severity_levels', 'alerts.severity_id', '=', 'severity_levels.id')
            ->selectRaw('severity_levels.name as severity, count(*) as total')
            ->groupBy('severity_levels.name')
            ->pluck('total', 'severity');

        $recentAlerts = Alert::with('severity', 'rule')
            ->orderByDesc('event_timestamp')
            ->limit(10)
            ->get();

        $data = [
            'alerts_total'    => $alertsTotal,
            'alerts_open'     => $alertsOpen,
            'alerts_by_level' => $alertsByLevel,
            'recent_alerts'   => $recentAlerts,
        ];

        // Datos adicionales para analyst y admin
        if (in_array($role, ['analyst', 'admin'])) {
            $data['raw_logs_today'] = RawLog::whereDate('created_at', today())->count();
        }

        // Datos exclusivos para admin
        if ($role === 'admin') {
            $data['total_users']  = User::count();
            $data['active_rules'] = CorrelationRule::where('enabled', true)->count();
        }

        return response()->json($data);
    }
}
```

---

### 5.3 — AlertController

**Archivo:** `app/Http/Controllers/AlertController.php`
**Acceso:** `analyst`, `admin`

Gestiona la consulta y actualización de estado de alertas. Soporta filtrado por múltiples parámetros y devuelve resultados paginados de 50 en 50.

```php
<?php

namespace App\Http\Controllers;

use App\Models\Alert;
use Illuminate\Http\Request;

class AlertController extends Controller
{
    // GET /api/alerts — Lista paginada con filtros opcionales
    public function index(Request $request)
    {
        $query = Alert::with('severity', 'rule');

        // Filtros opcionales por query string
        if ($request->filled('status'))        $query->where('status', $request->status);
        if ($request->filled('severity'))      $query->whereHas('severity', fn($q) => $q->where('name', $request->severity));
        if ($request->filled('source_system')) $query->where('source_system', $request->source_system);
        if ($request->filled('from'))          $query->where('event_timestamp', '>=', $request->from);
        if ($request->filled('to'))            $query->where('event_timestamp', '<=', $request->to);

        return response()->json(
            $query->orderByDesc('event_timestamp')->paginate(50)
        );
    }

    // GET /api/alerts/{id} — Detalle de una alerta
    public function show(Alert $alert)
    {
        return response()->json($alert->load('severity', 'rule'));
    }

    // PATCH /api/alerts/{id}/status — Actualiza el estado de una alerta
    public function updateStatus(Request $request, Alert $alert)
    {
        $request->validate([
            'status' => 'required|in:open,in_progress,resolved,dismissed',
        ]);

        $alert->update(['status' => $request->status]);

        return response()->json($alert);
    }
}
```

**Parámetros de filtrado disponibles en `GET /api/alerts`:**

| Parámetro | Tipo | Ejemplo |
|---|---|---|
| `status` | string | `?status=open` |
| `severity` | string | `?severity=high` |
| `source_system` | string | `?source_system=ssh` |
| `from` | datetime | `?from=2026-01-01T00:00:00` |
| `to` | datetime | `?to=2026-12-31T23:59:59` |

---

### 5.4 — RawLogController

**Archivo:** `app/Http/Controllers/RawLogController.php`
**Acceso:** `analyst`, `admin`

Permite consultar los logs en bruto almacenados por el logcollector Python. Solo lectura. Devuelve resultados paginados de 100 en 100.

```php
<?php

namespace App\Http\Controllers;

use App\Models\RawLog;
use Illuminate\Http\Request;

class RawLogController extends Controller
{
    // GET /api/raw-logs — Lista paginada con filtros opcionales
    public function index(Request $request)
    {
        $query = RawLog::query();

        if ($request->filled('source_system')) $query->where('source_system', $request->source_system);
        if ($request->filled('source_ip'))     $query->where('source_ip', $request->source_ip);
        if ($request->filled('event_type'))    $query->where('event_type', $request->event_type);
        if ($request->filled('from'))          $query->where('created_at', '>=', $request->from);
        if ($request->filled('to'))            $query->where('created_at', '<=', $request->to);

        return response()->json(
            $query->orderByDesc('created_at')->paginate(100)
        );
    }

    // GET /api/raw-logs/{id} — Detalle de un log en bruto
    public function show(RawLog $rawLog)
    {
        return response()->json($rawLog);
    }
}
```

---

### 5.5 — CorrelationRuleController

**Archivo:** `app/Http/Controllers/CorrelationRuleController.php`
**Acceso:** Solo `admin`

CRUD completo para la gestión de reglas de correlación. Cuando el administrador crea o modifica una regla desde el panel, Laravel la escribe en `alerts_db` y el correlator Python la recoge automáticamente.

```php
<?php

namespace App\Http\Controllers;

use App\Models\CorrelationRule;
use Illuminate\Http\Request;

class CorrelationRuleController extends Controller
{
    // GET /api/correlation-rules
    public function index()
    {
        return response()->json(
            CorrelationRule::with('severity')->orderBy('rule_name')->get()
        );
    }

    // POST /api/correlation-rules
    public function store(Request $request)
    {
        $data = $request->validate([
            'rule_name'   => 'required|string|unique:alerts_db.correlation_rules,rule_name',
            'description' => 'nullable|string',
            'severity_id' => 'required|integer',
            'enabled'     => 'boolean',
            'conditions'  => 'nullable|array',
        ]);

        return response()->json(CorrelationRule::create($data), 201);
    }

    // GET /api/correlation-rules/{id}
    public function show(CorrelationRule $correlationRule)
    {
        return response()->json($correlationRule->load('severity'));
    }

    // PUT/PATCH /api/correlation-rules/{id}
    public function update(Request $request, CorrelationRule $correlationRule)
    {
        $data = $request->validate([
            'rule_name'   => 'sometimes|string|unique:alerts_db.correlation_rules,rule_name,' . $correlationRule->id,
            'description' => 'nullable|string',
            'severity_id' => 'sometimes|integer',
            'enabled'     => 'boolean',
            'conditions'  => 'nullable|array',
        ]);

        $correlationRule->update($data);

        return response()->json($correlationRule);
    }

    // DELETE /api/correlation-rules/{id}
    public function destroy(CorrelationRule $correlationRule)
    {
        $correlationRule->delete();

        return response()->json(['message' => 'Regla eliminada.']);
    }
}
```

---

### 5.6 — UserController

**Archivo:** `app/Http/Controllers/UserController.php`
**Acceso:** Solo `admin`

CRUD completo para la gestión de usuarios de la plataforma. Las contraseñas se hashean automáticamente antes de guardar.

```php
<?php

namespace App\Http\Controllers;

use App\Models\User;
use App\Models\Role;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;

class UserController extends Controller
{
    // GET /api/users
    public function index()
    {
        return response()->json(User::with('role')->get());
    }

    // POST /api/users
    public function store(Request $request)
    {
        $data = $request->validate([
            'name'     => 'required|string|max:255',
            'email'    => 'required|email|unique:users',
            'password' => 'required|string|min:8',
            'role_id'  => 'required|exists:roles,id',
        ]);

        $data['password'] = Hash::make($data['password']);

        return response()->json(User::create($data)->load('role'), 201);
    }

    // GET /api/users/{id}
    public function show(User $user)
    {
        return response()->json($user->load('role'));
    }

    // PUT/PATCH /api/users/{id}
    public function update(Request $request, User $user)
    {
        $data = $request->validate([
            'name'     => 'sometimes|string|max:255',
            'email'    => 'sometimes|email|unique:users,email,' . $user->id,
            'password' => 'sometimes|string|min:8',
            'role_id'  => 'sometimes|exists:roles,id',
        ]);

        if (isset($data['password'])) {
            $data['password'] = Hash::make($data['password']);
        }

        $user->update($data);

        return response()->json($user->load('role'));
    }

    // DELETE /api/users/{id}
    public function destroy(User $user)
    {
        $user->delete();

        return response()->json(['message' => 'Usuario eliminado.']);
    }
}
```

---

### 5.7 — ReportController

**Archivo:** `app/Http/Controllers/ReportController.php`
**Acceso:** `analyst`, `admin`

Genera informes en formato CSV a partir de las alertas almacenadas. Los filtros aplicados quedan guardados junto al informe. Los administradores pueden ver todos los informes; los analistas solo los suyos.

```php
<?php

namespace App\Http\Controllers;

use App\Models\Report;
use App\Models\Alert;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Storage;

class ReportController extends Controller
{
    // GET /api/reports
    public function index(Request $request)
    {
        $reports = $request->user()->role?->name === 'admin'
            ? Report::with('user')->orderByDesc('created_at')->get()
            : $request->user()->reports()->orderByDesc('created_at')->get();

        return response()->json($reports);
    }

    // POST /api/reports — Genera un CSV con las alertas filtradas
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

        $query   = Alert::with('severity', 'rule');
        $filters = $data['filters'] ?? [];

        if (!empty($filters['status']))   $query->where('status', $filters['status']);
        if (!empty($filters['severity'])) $query->whereHas('severity', fn($q) => $q->where('name', $filters['severity']));
        if (!empty($filters['from']))     $query->where('event_timestamp', '>=', $filters['from']);
        if (!empty($filters['to']))       $query->where('event_timestamp', '<=', $filters['to']);

        $alerts   = $query->orderByDesc('event_timestamp')->get();
        $filename = 'reports/' . uniqid('report_') . '.csv';
        $rows     = ["ID,Título,Severidad,Sistema,IP,Usuario,Estado,Fecha"];

        foreach ($alerts as $alert) {
            $rows[] = implode(',', [
                $alert->id,
                '"' . str_replace('"', '""', $alert->title) . '"',
                $alert->severity?->name,
                $alert->source_system,
                $alert->source_ip,
                $alert->username,
                $alert->status,
                $alert->event_timestamp,
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

    // GET /api/reports/{id}
    public function show(Report $report)
    {
        $this->authorize('view', $report);
        return response()->json($report);
    }

    // GET /api/reports/{id}/download — Descarga el CSV
    public function download(Report $report)
    {
        $this->authorize('view', $report);

        if (! Storage::exists($report->file_path)) {
            return response()->json(['message' => 'Archivo no encontrado.'], 404);
        }

        return Storage::download($report->file_path, $report->title . '.csv');
    }

    // DELETE /api/reports/{id}
    public function destroy(Report $report)
    {
        $this->authorize('delete', $report);
        Storage::delete($report->file_path);
        $report->delete();

        return response()->json(['message' => 'Informe eliminado.']);
    }
}
```

---

## 6. Policies (Autorización)

Las policies son clases PHP que centralizan la lógica de autorización para cada modelo. Se registran en `AppServiceProvider` y se invocan automáticamente con `$this->authorize()` en los controladores o con el middleware `can:`.

**Registro en `app/Providers/AppServiceProvider.php`:**

```php
Gate::policy(Alert::class,           AlertPolicy::class);
Gate::policy(RawLog::class,          RawLogPolicy::class);
Gate::policy(CorrelationRule::class, CorrelationRulePolicy::class);
Gate::policy(User::class,            UserPolicy::class);
Gate::policy(Report::class,          ReportPolicy::class);
```

---

### 6.1 — AlertPolicy

```php
class AlertPolicy
{
    public function viewAny(User $user): bool
    {
        return in_array($user->role?->name, ['analyst', 'admin']);
    }

    public function view(User $user, Alert $alert): bool
    {
        return in_array($user->role?->name, ['analyst', 'admin']);
    }

    public function update(User $user, Alert $alert): bool
    {
        return in_array($user->role?->name, ['analyst', 'admin']);
    }
}
```

### 6.2 — RawLogPolicy

```php
class RawLogPolicy
{
    public function viewAny(User $user): bool
    {
        return in_array($user->role?->name, ['analyst', 'admin']);
    }

    public function view(User $user, RawLog $rawLog): bool
    {
        return in_array($user->role?->name, ['analyst', 'admin']);
    }
}
```

### 6.3 — CorrelationRulePolicy

```php
class CorrelationRulePolicy
{
    public function viewAny(User $user): bool  { return $user->role?->name === 'admin'; }
    public function view(User $user, CorrelationRule $rule): bool { return $user->role?->name === 'admin'; }
    public function create(User $user): bool   { return $user->role?->name === 'admin'; }
    public function update(User $user, CorrelationRule $rule): bool { return $user->role?->name === 'admin'; }
    public function delete(User $user, CorrelationRule $rule): bool { return $user->role?->name === 'admin'; }
}
```

### 6.4 — UserPolicy

```php
class UserPolicy
{
    public function viewAny(User $user): bool { return $user->role?->name === 'admin'; }
    public function view(User $user, User $target): bool
    {
        return $user->role?->name === 'admin' || $user->id === $target->id;
    }
    public function create(User $user): bool  { return $user->role?->name === 'admin'; }
    public function update(User $user, User $target): bool { return $user->role?->name === 'admin'; }
    public function delete(User $user, User $target): bool
    {
        // Un admin no puede eliminarse a sí mismo
        return $user->role?->name === 'admin' && $user->id !== $target->id;
    }
}
```

### 6.5 — ReportPolicy

```php
class ReportPolicy
{
    public function viewAny(User $user): bool { return in_array($user->role?->name, ['analyst', 'admin']); }
    public function view(User $user, Report $report): bool
    {
        // Admin ve todos; analista solo los suyos
        return $user->role?->name === 'admin' || $user->id === $report->user_id;
    }
    public function create(User $user): bool { return in_array($user->role?->name, ['analyst', 'admin']); }
    public function delete(User $user, Report $report): bool
    {
        return $user->role?->name === 'admin' || $user->id === $report->user_id;
    }
}
```

**Tabla resumen de permisos por rol:**

| Acción | user | analyst | admin |
|---|:---:|:---:|:---:|
| Login / Logout / Me | ✓ | ✓ | ✓ |
| Ver dashboard | ✓ | ✓ | ✓ |
| Ver alertas | ✗ | ✓ | ✓ |
| Cambiar estado de alerta | ✗ | ✓ | ✓ |
| Ver logs en bruto | ✗ | ✓ | ✓ |
| Generar y descargar informes | ✗ | ✓ | ✓ |
| Gestionar reglas de correlación | ✗ | ✗ | ✓ |
| Gestionar usuarios | ✗ | ✗ | ✓ |

---

## 7. Rutas API

**Archivo:** `routes/api.php`

Todas las rutas están prefijadas con `/api`. Las rutas protegidas requieren el header `Authorization: Bearer {token}`.

```
POST   /api/login                              → AuthController@login
POST   /api/logout                  [auth]     → AuthController@logout
GET    /api/me                      [auth]     → AuthController@me

GET    /api/dashboard               [auth]     → DashboardController@index

GET    /api/alerts                  [analyst+] → AlertController@index
GET    /api/alerts/{id}             [analyst+] → AlertController@show
PATCH  /api/alerts/{id}/status      [analyst+] → AlertController@updateStatus

GET    /api/raw-logs                [analyst+] → RawLogController@index
GET    /api/raw-logs/{id}           [analyst+] → RawLogController@show

GET    /api/reports                 [analyst+] → ReportController@index
POST   /api/reports                 [analyst+] → ReportController@store
GET    /api/reports/{id}            [analyst+] → ReportController@show
GET    /api/reports/{id}/download   [analyst+] → ReportController@download
DELETE /api/reports/{id}            [analyst+] → ReportController@destroy

GET    /api/correlation-rules       [admin]    → CorrelationRuleController@index
POST   /api/correlation-rules       [admin]    → CorrelationRuleController@store
GET    /api/correlation-rules/{id}  [admin]    → CorrelationRuleController@show
PUT    /api/correlation-rules/{id}  [admin]    → CorrelationRuleController@update
DELETE /api/correlation-rules/{id}  [admin]    → CorrelationRuleController@destroy

GET    /api/users                   [admin]    → UserController@index
POST   /api/users                   [admin]    → UserController@store
GET    /api/users/{id}              [admin]    → UserController@show
PUT    /api/users/{id}              [admin]    → UserController@update
DELETE /api/users/{id}              [admin]    → UserController@destroy
```

Total: **24 endpoints**

---

## 8. Pruebas documentadas

Todas las pruebas se realizan contra `http://localhost:8000` con el servidor Laravel activo (`php artisan serve`). La autenticación es mediante token Bearer obtenido en el login.

> **Variables usadas en los ejemplos:**
> - `TOKEN` = token obtenido al hacer login
> - `BASE` = `http://localhost:8000/api`

---

### PRUEBA 1 — Login correcto

**Objetivo:** Verificar que el sistema devuelve un token válido con las credenciales correctas.

**Petición:**
```bash
curl -X POST http://localhost:8000/api/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@logsentinel.com","password":"Admin1234!"}'
```

**Respuesta esperada (HTTP 200):**
```json
{
  "token": "1|ewRbEw3tF9rG3fUN6n1h4V8ZLLdobxITDvZT3XeW6877e15a",
  "user": {
    "id": 1,
    "name": "Administrador",
    "email": "admin@logsentinel.com",
    "role": "admin"
  }
}
```

---

### PRUEBA 2 — Login con credenciales incorrectas

**Objetivo:** Verificar que el sistema rechaza credenciales inválidas con HTTP 422.

**Petición:**
```bash
curl -X POST http://localhost:8000/api/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@logsentinel.com","password":"contraseña_incorrecta"}'
```

**Respuesta esperada (HTTP 422):**
```json
{
  "message": "Credenciales incorrectas.",
  "errors": {
    "email": ["Credenciales incorrectas."]
  }
}
```

---

### PRUEBA 3 — Obtener datos del usuario autenticado

**Objetivo:** Verificar que `/api/me` devuelve los datos del usuario cuyo token se usa.

**Petición:**
```bash
curl http://localhost:8000/api/me \
  -H "Authorization: Bearer {TOKEN}"
```

**Respuesta esperada (HTTP 200):**
```json
{
  "id": 1,
  "name": "Administrador",
  "email": "admin@logsentinel.com",
  "role": "admin"
}
```

---

### PRUEBA 4 — Acceso sin token (no autenticado)

**Objetivo:** Verificar que las rutas protegidas rechazan peticiones sin token.

**Petición:**
```bash
curl http://localhost:8000/api/alerts
```

**Respuesta esperada (HTTP 401):**
```json
{
  "message": "Unauthenticated."
}
```

---

### PRUEBA 5 — Dashboard como administrador

**Objetivo:** Verificar que el dashboard devuelve estadísticas completas incluyendo usuarios y reglas activas.

**Petición:**
```bash
curl http://localhost:8000/api/dashboard \
  -H "Authorization: Bearer {TOKEN}"
```

**Respuesta esperada (HTTP 200):**
```json
{
  "alerts_total": 3,
  "alerts_open": 3,
  "alerts_by_level": {
    "high": 2,
    "critical": 1
  },
  "recent_alerts": [...],
  "raw_logs_today": 6,
  "total_users": 1,
  "active_rules": 11
}
```

---

### PRUEBA 6 — Listar alertas

**Objetivo:** Verificar que se devuelven todas las alertas con paginación y relaciones cargadas.

**Petición:**
```bash
curl http://localhost:8000/api/alerts \
  -H "Authorization: Bearer {TOKEN}"
```

**Respuesta esperada (HTTP 200):**
```json
{
  "current_page": 1,
  "data": [
    {
      "id": 3,
      "rule_id": 5,
      "severity_id": 4,
      "source_ip": "10.10.10.99",
      "username": "root",
      "source_system": "ssh",
      "title": "Posible fuerza bruta SSH",
      "message": "...",
      "metadata": {...},
      "event_timestamp": "2026-03-16T18:17:23.000000Z",
      "status": "open",
      "severity": { "id": 4, "name": "critical", "level": 4 },
      "rule": { "id": 5, "rule_name": "failed_login_bruteforce", "enabled": true }
    }
  ],
  "total": 3,
  "per_page": 50
}
```

---

### PRUEBA 7 — Filtrar alertas por severidad

**Objetivo:** Verificar que el filtrado por severidad funciona correctamente.

**Petición:**
```bash
curl "http://localhost:8000/api/alerts?severity=high" \
  -H "Authorization: Bearer {TOKEN}"
```

**Respuesta esperada (HTTP 200):** Solo alertas con severidad `high`.

---

### PRUEBA 8 — Ver detalle de una alerta

**Objetivo:** Verificar que se obtiene el detalle completo de una alerta concreta.

**Petición:**
```bash
curl http://localhost:8000/api/alerts/2 \
  -H "Authorization: Bearer {TOKEN}"
```

**Respuesta esperada (HTTP 200):**
```json
{
  "id": 2,
  "title": "Intentos de fuerza bruta",
  "severity": { "name": "high" },
  "rule": { "rule_name": "failed_login_bruteforce" },
  "status": "open",
  "source_ip": "10.10.10.99"
}
```

---

### PRUEBA 9 — Actualizar estado de una alerta

**Objetivo:** Verificar que un analista puede cambiar el estado de una alerta.

**Petición:**
```bash
curl -X PATCH http://localhost:8000/api/alerts/2/status \
  -H "Authorization: Bearer {TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"status":"in_progress"}'
```

**Respuesta esperada (HTTP 200):**
```json
{
  "id": 2,
  "status": "in_progress",
  ...
}
```

---

### PRUEBA 10 — Estado inválido al actualizar alerta

**Objetivo:** Verificar que la validación rechaza estados no permitidos.

**Petición:**
```bash
curl -X PATCH http://localhost:8000/api/alerts/2/status \
  -H "Authorization: Bearer {TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"status":"cerrado"}'
```

**Respuesta esperada (HTTP 422):**
```json
{
  "message": "The selected status is invalid.",
  "errors": {
    "status": ["The selected status is invalid."]
  }
}
```

---

### PRUEBA 11 — Ver logs en bruto

**Objetivo:** Verificar que la API devuelve los logs recibidos por el logcollector.

**Petición:**
```bash
curl http://localhost:8000/api/raw-logs \
  -H "Authorization: Bearer {TOKEN}"
```

**Respuesta esperada (HTTP 200):** Lista paginada con los logs guardados por Python, incluyendo el campo `raw_data` con el payload original completo.

---

### PRUEBA 12 — Crear un usuario nuevo

**Objetivo:** Verificar que un administrador puede crear usuarios con rol asignado.

**Petición:**
```bash
curl -X POST http://localhost:8000/api/users \
  -H "Authorization: Bearer {TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Ana García",
    "email": "ana@logsentinel.com",
    "password": "Analyst1234!",
    "role_id": 2
  }'
```

**Respuesta esperada (HTTP 201):**
```json
{
  "id": 2,
  "name": "Ana García",
  "email": "ana@logsentinel.com",
  "role": { "id": 2, "name": "analyst" }
}
```

---

### PRUEBA 13 — Email duplicado al crear usuario

**Objetivo:** Verificar que el sistema rechaza emails ya existentes.

**Petición:**
```bash
curl -X POST http://localhost:8000/api/users \
  -H "Authorization: Bearer {TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"name":"Duplicado","email":"admin@logsentinel.com","password":"Test1234!","role_id":1}'
```

**Respuesta esperada (HTTP 422):**
```json
{
  "message": "The email has already been taken.",
  "errors": {
    "email": ["The email has already been taken."]
  }
}
```

---

### PRUEBA 14 — Listar reglas de correlación

**Objetivo:** Verificar que el administrador puede ver todas las reglas de correlación.

**Petición:**
```bash
curl http://localhost:8000/api/correlation-rules \
  -H "Authorization: Bearer {TOKEN}"
```

**Respuesta esperada (HTTP 200):**
```json
[
  { "id": 3, "rule_name": "blacklist_ip", "enabled": true, "severity": null },
  { "id": 4, "rule_name": "dos_detection", "enabled": true, "severity": null },
  { "id": 5, "rule_name": "failed_login_bruteforce", "enabled": true, "severity": null },
  ...
]
```

---

### PRUEBA 15 — Desactivar una regla de correlación

**Objetivo:** Verificar que un administrador puede deshabilitar una regla.

**Petición:**
```bash
curl -X PATCH http://localhost:8000/api/correlation-rules/4 \
  -H "Authorization: Bearer {TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"enabled": false}'
```

**Respuesta esperada (HTTP 200):**
```json
{
  "id": 4,
  "rule_name": "dos_detection",
  "enabled": false
}
```

---

### PRUEBA 16 — Generar un informe CSV

**Objetivo:** Verificar que se genera un informe con las alertas filtradas.

**Petición:**
```bash
curl -X POST http://localhost:8000/api/reports \
  -H "Authorization: Bearer {TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Informe alertas SSH - Marzo 2026",
    "filters": {
      "source_system": "ssh",
      "status": "open"
    }
  }'
```

**Respuesta esperada (HTTP 201):**
```json
{
  "id": 1,
  "title": "Informe alertas SSH - Marzo 2026",
  "filters": { "source_system": "ssh", "status": "open" },
  "file_path": "reports/report_67d789abc1234.csv",
  "user_id": 1
}
```

---

### PRUEBA 17 — Descargar el informe CSV

**Objetivo:** Verificar que se puede descargar el archivo CSV generado.

**Petición:**
```bash
curl -O -J http://localhost:8000/api/reports/1/download \
  -H "Authorization: Bearer {TOKEN}"
```

**Respuesta esperada:** Descarga del archivo `Informe alertas SSH - Marzo 2026.csv` con contenido:
```
ID,Título,Severidad,Sistema,IP,Usuario,Estado,Fecha
3,"Posible fuerza bruta SSH",critical,ssh,10.10.10.99,root,open,2026-03-16...
2,"Intentos de fuerza bruta",high,ssh,10.10.10.99,root,in_progress,2026-03-16...
```

---

### PRUEBA 18 — Flujo completo de generación de alerta

**Objetivo:** Verificar el flujo end-to-end desde el envío de un log hasta la aparición de la alerta en la API de Laravel.

**Paso 1 — Enviar 6 eventos de login fallido al logcollector Python:**
```bash
for i in {1..6}; do
  curl -X POST http://20.238.17.71:5000/log \
    -H "Content-Type: application/json" \
    -d '{"source_system":"ssh","event_type":"failed","username":"root","source_ip":"10.10.10.99"}'
done
```

**Flujo interno:**
```
logcollector (puerto 5000)
    ↓ guarda en raw_logs (log_collector DB)
    ↓ envía a normalizer (puerto 6000)
normalizer
    ↓ detecta fuente: ssh
    ↓ normaliza event_type → "login_failed"
    ↓ envía a correlator (puerto 7000)
correlator
    ↓ evalúa regla failed_login_bruteforce (threshold=5, window=180s)
    ↓ al 6º evento: genera alerta
    ↓ inserta en alerts (alerts_db)
```

**Paso 2 — Verificar la alerta via API Laravel:**
```bash
curl http://localhost:8000/api/alerts?source_system=ssh \
  -H "Authorization: Bearer {TOKEN}"
```

**Respuesta esperada:** La alerta generada aparece con `title: "Intentos de fuerza bruta"`, `source_ip: "10.10.10.99"`, `status: "open"`.

---

### PRUEBA 19 — Logout e invalidación del token

**Objetivo:** Verificar que tras el logout el token queda invalidado.

**Paso 1 — Hacer logout:**
```bash
curl -X POST http://localhost:8000/api/logout \
  -H "Authorization: Bearer {TOKEN}"
```

**Respuesta esperada (HTTP 200):**
```json
{ "message": "Sesión cerrada." }
```

**Paso 2 — Intentar usar el token invalidado:**
```bash
curl http://localhost:8000/api/alerts \
  -H "Authorization: Bearer {TOKEN}"
```

**Respuesta esperada (HTTP 401):**
```json
{ "message": "Unauthenticated." }
```

---

*Documentación generada el 16/03/2026 — LogSentinel v1.0*
