import { Component, inject, AfterViewInit, ElementRef } from '@angular/core';
import { RouterLink } from '@angular/router';
import { AuthService } from '../../core/services/auth.service';

@Component({
  selector: 'app-landing',
  imports: [RouterLink],
  templateUrl: './landing.html',
  styleUrl: './landing.scss'
})
export class LandingPage implements AfterViewInit {
  auth       = inject(AuthService);
  el         = inject(ElementRef);
  isLoggedIn = this.auth.isLoggedIn();

  ngAfterViewInit(): void {
    const items = this.el.nativeElement.querySelectorAll('[data-reveal]') as NodeListOf<HTMLElement>;

    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach(entry => {
          if (!entry.isIntersecting) return;
          const delay = Number((entry.target as HTMLElement).dataset['revealDelay'] ?? 0);
          setTimeout(() => entry.target.classList.add('is-visible'), delay);
          observer.unobserve(entry.target);
        });
      },
      { threshold: 0.1, rootMargin: '0px 0px -40px 0px' }
    );

    items.forEach(item => observer.observe(item));
  }
}
