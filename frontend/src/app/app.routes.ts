import { Routes } from '@angular/router';
import { authGuard } from './core/guards/auth.guard';

export const routes: Routes = [
  {
    path: '',
    loadComponent: () => import('./pages/landing/landing').then(m => m.LandingPage)
  },
  {
    path: 'login',
    loadComponent: () => import('./pages/login/login').then(m => m.LoginPage)
  },
  {
    path: 'app',
    loadComponent: () => import('./layout/layout').then(m => m.LayoutComponent),
    canActivate: [authGuard],
    children: [
      { path: '', redirectTo: 'dashboard', pathMatch: 'full' },
      {
        path: 'dashboard',
        loadComponent: () => import('./pages/dashboard/dashboard').then(m => m.DashboardPage)
      },
      {
        path: 'alerts',
        loadComponent: () => import('./pages/alerts/alerts').then(m => m.AlertsPage)
      },
      {
        path: 'logs',
        loadComponent: () => import('./pages/logs/logs').then(m => m.LogsPage)
      },
      {
        path: 'rules',
        loadComponent: () => import('./pages/rules/rules').then(m => m.RulesPage)
      },
      {
        path: 'reports',
        loadComponent: () => import('./pages/reports/reports').then(m => m.ReportsPage)
      },
      {
        path: 'users',
        loadComponent: () => import('./pages/users/users').then(m => m.UsersPage)
      },
      {
        path: 'systems',
        loadComponent: () => import('./pages/systems/systems').then(m => m.SystemsPage)
      },
    ]
  },
  { path: '**', redirectTo: '' }
];
