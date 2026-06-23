/**
 * BIGIL Forensic Platform — Premium Animations v2.0
 * GSAP-powered: counters, stagger reveal, 3D tilt, magnetic buttons,
 * particle canvas background, cursor glow, page transitions
 */

// ── GSAP Available Check ──────────────────────────────────────────────────────
const GSAP = (typeof gsap !== 'undefined') ? gsap : null;

// ══════════════════════════════════════════════════════════════════════════════
// 0. FORCE-VISIBLE FAILSAFE (never hide app content if CDN/GSAP fails)
// ══════════════════════════════════════════════════════════════════════════════
function revealAllContent() {
  const selectors = [
    '[data-animate]', '.card', '.stat-card', '.page-header', '.nav-item',
    '.log-line', '.soc-panel', '.login-hero', '.login-card-wrap', '.login-story',
    '.app-layout', '.main-content', '.page-content', '.sidebar'
  ];
  selectors.forEach(sel => {
    document.querySelectorAll(sel).forEach(el => {
      el.style.opacity = '1';
      el.style.transform = 'none';
      el.style.visibility = 'visible';
    });
  });
}

// ══════════════════════════════════════════════════════════════════════════════
// 1. LOADING SCREEN
// ══════════════════════════════════════════════════════════════════════════════
function dismissLoadingScreen() {
  const screen = document.getElementById('loading-screen');
  if (!screen || screen.dataset.dismissed) return;
  screen.dataset.dismissed = '1';
  if (GSAP) {
    gsap.to(screen, {
      opacity: 0,
      duration: 0.4,
      ease: 'power2.inOut',
      onComplete: () => screen.remove()
    });
  } else {
    screen.style.transition = 'opacity 0.4s ease';
    screen.style.opacity = '0';
    setTimeout(() => screen.remove(), 400);
  }
}

function initLoadingScreen() {
  if (!document.getElementById('loading-screen')) return;
  setTimeout(dismissLoadingScreen, 1200);
  // Hard failsafe — never block the UI if CDN scripts fail to load
  setTimeout(dismissLoadingScreen, 3500);
}

// ══════════════════════════════════════════════════════════════════════════════
// 2. CURSOR GLOW (Mouse-Follow Light)
// ══════════════════════════════════════════════════════════════════════════════
function initCursorGlow() {
  const glow = document.getElementById('cursor-glow');
  if (!glow) return;

  let mouseX = 0, mouseY = 0;
  let glowX = 0, glowY = 0;

  document.addEventListener('mousemove', (e) => {
    mouseX = e.clientX;
    mouseY = e.clientY;
  });

  function animateGlow() {
    glowX += (mouseX - glowX) * 0.08;
    glowY += (mouseY - glowY) * 0.08;
    glow.style.left = glowX + 'px';
    glow.style.top  = glowY + 'px';
    requestAnimationFrame(animateGlow);
  }
  animateGlow();
}

// ══════════════════════════════════════════════════════════════════════════════
// 3. COUNTER ANIMATION (Stat Cards)
// ══════════════════════════════════════════════════════════════════════════════
function animateCounters() {
  const counterEls = document.querySelectorAll('.stat-value');
  counterEls.forEach(el => {
    const raw = el.textContent.trim();
    const num = parseFloat(raw.replace(/[^0-9.]/g, ''));
    if (isNaN(num) || num === 0) return;

    const suffix = raw.replace(/[0-9.]/g, '').trim();
    el.textContent = '0' + suffix;

    const start = performance.now();
    const duration = 1400;

    function tick(now) {
      const elapsed = now - start;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3); // ease-out cubic
      const current = Math.floor(eased * num);
      el.textContent = current.toLocaleString('en-IN') + (suffix ? suffix : '');
      if (progress < 1) requestAnimationFrame(tick);
      else el.textContent = num.toLocaleString('en-IN') + (suffix ? suffix : '');
    }
    requestAnimationFrame(tick);
  });
}

// ══════════════════════════════════════════════════════════════════════════════
// 4. GSAP SCROLL & STAGGER ANIMATIONS
// ══════════════════════════════════════════════════════════════════════════════
function initGSAPAnimations() {
  if (!GSAP) {
    revealAllContent();
    return;
  }

  // Page entrance: stat cards
  gsap.from('.stat-card', {
    y: 30,
    opacity: 0,
    duration: 0.6,
    stagger: 0.08,
    ease: 'power3.out',
    delay: 0.2,
    clearProps: 'all'
  });

  // Cards
  gsap.from('.card', {
    y: 24,
    opacity: 0,
    duration: 0.7,
    stagger: 0.1,
    ease: 'power3.out',
    delay: 0.4,
    clearProps: 'all'
  });

  // Nav items stagger
  gsap.from('.nav-item', {
    x: -20,
    opacity: 0,
    duration: 0.5,
    stagger: 0.06,
    ease: 'power2.out',
    delay: 0.1,
    clearProps: 'all'
  });

  // Page header
  gsap.from('.page-header', {
    y: -20,
    opacity: 0,
    duration: 0.6,
    ease: 'power3.out',
    clearProps: 'all'
  });

  // Table rows — stagger
  const tables = document.querySelectorAll('.data-table tbody');
  tables.forEach(tbody => {
    const rows = tbody.querySelectorAll('tr');
    gsap.from(rows, {
      opacity: 0,
      x: -10,
      duration: 0.4,
      stagger: 0.05,
      ease: 'power2.out',
      delay: 0.6,
      clearProps: 'all'
    });
  });

  // Alert items
  gsap.from('.alert-item', {
    opacity: 0,
    x: 16,
    duration: 0.5,
    stagger: 0.08,
    ease: 'power2.out',
    delay: 0.5,
    clearProps: 'all'
  });

  // Threat ticker
  gsap.from('.threat-ticker', {
    opacity: 0,
    y: -8,
    duration: 0.5,
    ease: 'power2.out',
    clearProps: 'all'
  });
}

// ══════════════════════════════════════════════════════════════════════════════
// 5. 3D CARD TILT (Mouse Perspective)
// ══════════════════════════════════════════════════════════════════════════════
function init3DTilt() {
  const cards = document.querySelectorAll('.stat-card, .card');

  cards.forEach(card => {
    card.addEventListener('mousemove', (e) => {
      const rect = card.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;
      const centerX = rect.width / 2;
      const centerY = rect.height / 2;
      const rotateX = ((y - centerY) / centerY) * -6;
      const rotateY = ((x - centerX) / centerX) * 6;

      card.style.transform = `perspective(1000px) rotateX(${rotateX}deg) rotateY(${rotateY}deg) translateZ(4px)`;
    });

    card.addEventListener('mouseleave', () => {
      card.style.transition = 'transform 0.5s cubic-bezier(0.16, 1, 0.3, 1)';
      card.style.transform = 'perspective(1000px) rotateX(0) rotateY(0) translateZ(0)';
      setTimeout(() => { card.style.transition = ''; }, 500);
    });

    card.addEventListener('mouseenter', () => {
      card.style.transition = 'transform 0.1s linear';
    });
  });
}

// ══════════════════════════════════════════════════════════════════════════════
// 6. MAGNETIC BUTTONS
// ══════════════════════════════════════════════════════════════════════════════
function initMagneticButtons() {
  document.querySelectorAll('.btn-primary').forEach(btn => {
    btn.addEventListener('mousemove', (e) => {
      const rect = btn.getBoundingClientRect();
      const x = e.clientX - rect.left - rect.width / 2;
      const y = e.clientY - rect.top  - rect.height / 2;
      btn.style.transform = `translate(${x * 0.2}px, ${y * 0.2}px)`;
    });

    btn.addEventListener('mouseleave', () => {
      btn.style.transition = 'transform 0.5s cubic-bezier(0.16, 1, 0.3, 1)';
      btn.style.transform = 'translate(0, 0)';
      setTimeout(() => { btn.style.transition = ''; }, 500);
    });
  });
}

// ══════════════════════════════════════════════════════════════════════════════
// 7. CANVAS PARTICLE BACKGROUND
// ══════════════════════════════════════════════════════════════════════════════
function initParticles() {
  const canvas = document.getElementById('particle-canvas');
  if (!canvas) return;

  const ctx = canvas.getContext('2d');
  let W = canvas.width = window.innerWidth;
  let H = canvas.height = window.innerHeight;

  const MAX_PARTICLES = 80;
  const LINK_DIST = 140;

  const particles = Array.from({ length: MAX_PARTICLES }, () => ({
    x: Math.random() * W,
    y: Math.random() * H,
    vx: (Math.random() - 0.5) * 0.4,
    vy: (Math.random() - 0.5) * 0.4,
    r: Math.random() * 1.5 + 0.5,
    opacity: Math.random() * 0.4 + 0.1
  }));

  let mouse = { x: -999, y: -999 };
  let hidden = false;

  document.addEventListener('mousemove', e => { mouse.x = e.clientX; mouse.y = e.clientY; });
  document.addEventListener('visibilitychange', () => { hidden = document.hidden; });

  window.addEventListener('resize', () => {
    W = canvas.width = window.innerWidth;
    H = canvas.height = window.innerHeight;
  });

  function draw() {
    if (hidden) { requestAnimationFrame(draw); return; }

    ctx.clearRect(0, 0, W, H);

    particles.forEach(p => {
      // Move
      p.x += p.vx;
      p.y += p.vy;
      if (p.x < 0 || p.x > W) p.vx *= -1;
      if (p.y < 0 || p.y > H) p.vy *= -1;

      // Mouse repel (subtle)
      const dx = p.x - mouse.x;
      const dy = p.y - mouse.y;
      const dist = Math.sqrt(dx * dx + dy * dy);
      if (dist < 80) {
        const force = (80 - dist) / 80 * 0.8;
        p.vx += (dx / dist) * force * 0.05;
        p.vy += (dy / dist) * force * 0.05;
      }

      // Draw dot
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(212, 212, 212, ${p.opacity})`;
      ctx.fill();
    });

    // Draw links
    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const dx = particles[i].x - particles[j].x;
        const dy = particles[i].y - particles[j].y;
        const d = Math.sqrt(dx * dx + dy * dy);
        if (d < LINK_DIST) {
          const alpha = (1 - d / LINK_DIST) * 0.15;
          ctx.beginPath();
          ctx.moveTo(particles[i].x, particles[i].y);
          ctx.lineTo(particles[j].x, particles[j].y);
          ctx.strokeStyle = `rgba(212, 212, 212, ${alpha})`;
          ctx.lineWidth = 0.5;
          ctx.stroke();
        }
      }
    }

    requestAnimationFrame(draw);
  }

  draw();
}

// ══════════════════════════════════════════════════════════════════════════════
// 8. CHART.JS GLOBAL DEFAULTS (Premium Styling)
// ══════════════════════════════════════════════════════════════════════════════
function initChartDefaults() {
  if (typeof Chart === 'undefined') return;
  Chart.defaults.color = '#94A3B8';
  Chart.defaults.borderColor = 'rgba(212,212,212,0.08)';
  Chart.defaults.font.family = 'Inter, sans-serif';
  Chart.defaults.font.size = 12;
  Chart.defaults.plugins.legend.labels.color = '#94A3B8';
  Chart.defaults.plugins.legend.labels.usePointStyle = true;
  Chart.defaults.plugins.legend.labels.pointStyleWidth = 8;
  Chart.defaults.plugins.tooltip.backgroundColor = 'rgba(3,13,28,0.95)';
  Chart.defaults.plugins.tooltip.borderColor = 'rgba(212,212,212,0.2)';
  Chart.defaults.plugins.tooltip.borderWidth = 1;
  Chart.defaults.plugins.tooltip.titleColor = '#E2E8F0';
  Chart.defaults.plugins.tooltip.bodyColor = '#94A3B8';
  Chart.defaults.plugins.tooltip.padding = 12;
  Chart.defaults.plugins.tooltip.cornerRadius = 8;
}

// ══════════════════════════════════════════════════════════════════════════════
// 9. LIVE CLOCK
// ══════════════════════════════════════════════════════════════════════════════
function initClock() {
  function tick() {
    const el = document.getElementById('live-clock');
    if (!el) return;
    const now = new Date();
    el.textContent = now.toLocaleString('en-IN', {
      timeZone: 'Asia/Kolkata',
      hour12: false,
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit'
    }).replace(/\//g, '-') + ' IST';
  }
  tick();
  setInterval(tick, 1000);
}

// ══════════════════════════════════════════════════════════════════════════════
// 10. FLASH MESSAGE AUTO-DISMISS
// ══════════════════════════════════════════════════════════════════════════════
function initFlashMessages() {
  setTimeout(() => {
    document.querySelectorAll('.flash-msg').forEach(el => {
      if (GSAP) {
        gsap.to(el, { opacity: 0, y: -8, duration: 0.3, onComplete: () => el.remove() });
      } else {
        el.style.transition = 'opacity 0.3s';
        el.style.opacity = '0';
        setTimeout(() => el.remove(), 300);
      }
    });
  }, 5000);
}

// ══════════════════════════════════════════════════════════════════════════════
// 11. SIDEBAR ACTIVE INDICATOR GLOW
// ══════════════════════════════════════════════════════════════════════════════
function initSidebarGlow() {
  const active = document.querySelector('.nav-item.active');
  if (!active || !GSAP) return;

  gsap.from(active, {
    backgroundColor: 'transparent',
    duration: 0.6,
    ease: 'power2.out'
  });
}

// ══════════════════════════════════════════════════════════════════════════════
// 12. MOBILE SIDEBAR TOGGLE
// ══════════════════════════════════════════════════════════════════════════════
function initMobileNav() {
  const btn = document.getElementById('mobile-menu-btn');
  const sidebar = document.getElementById('sidebar');
  const overlay = document.getElementById('sidebar-overlay');
  if (!btn || !sidebar) return;

  function close() {
    btn.classList.remove('active');
    btn.setAttribute('aria-expanded', 'false');
    sidebar.classList.remove('open');
    overlay?.classList.remove('active');
    document.body.style.overflow = '';
  }

  function open() {
    btn.classList.add('active');
    btn.setAttribute('aria-expanded', 'true');
    sidebar.classList.add('open');
    overlay?.classList.add('active');
    document.body.style.overflow = 'hidden';
  }

  btn.addEventListener('click', () => {
    sidebar.classList.contains('open') ? close() : open();
  });

  overlay?.addEventListener('click', close);
  sidebar.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', () => { if (window.innerWidth <= 768) close(); });
  });
}

// ══════════════════════════════════════════════════════════════════════════════
// 13. SCROLL-TRIGGERED REVEALS
// ══════════════════════════════════════════════════════════════════════════════
function initScrollReveals() {
  if (!GSAP || typeof ScrollTrigger === 'undefined') {
    revealAllContent();
    return;
  }
  try {
    gsap.registerPlugin(ScrollTrigger);
    gsap.utils.toArray('[data-animate]').forEach(el => {
      if (el.closest('.login-body')) return;
      gsap.from(el, {
        scrollTrigger: { trigger: el, start: 'top 88%', toggleActions: 'play none none none' },
        y: 16,
        opacity: 0.85,
        duration: 0.5,
        ease: 'power2.out',
        clearProps: 'all'
      });
    });
  } catch (e) {
    revealAllContent();
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// 14. MAGNETIC BUTTONS (all .btn-magnetic)
// ══════════════════════════════════════════════════════════════════════════════
function initAllMagneticButtons() {
  document.querySelectorAll('.btn-primary, .btn-magnetic').forEach(btn => {
    if (btn.dataset.magnetic) return;
    btn.dataset.magnetic = '1';
    btn.addEventListener('mousemove', (e) => {
      const rect = btn.getBoundingClientRect();
      const x = e.clientX - rect.left - rect.width / 2;
      const y = e.clientY - rect.top - rect.height / 2;
      btn.style.transform = `translate(${x * 0.18}px, ${y * 0.18}px)`;
    });
    btn.addEventListener('mouseleave', () => {
      btn.style.transition = 'transform 0.5s cubic-bezier(0.16, 1, 0.3, 1)';
      btn.style.transform = 'translate(0, 0)';
      setTimeout(() => { btn.style.transition = ''; }, 500);
    });
  });
}

// ══════════════════════════════════════════════════════════════════════════════
// INIT ALL
// ══════════════════════════════════════════════════════════════════════════════
document.addEventListener('DOMContentLoaded', () => {
  revealAllContent();
  initLoadingScreen();
  initCursorGlow();
  initChartDefaults();
  initClock();
  initFlashMessages();
  initMobileNav();

  setTimeout(() => {
    initGSAPAnimations();
    initScrollReveals();
    animateCounters();
    init3DTilt();
    initMagneticButtons();
    initAllMagneticButtons();
    initParticles();
    initSidebarGlow();
    revealAllContent();
  }, 100);

  setTimeout(revealAllContent, 1500);
  setTimeout(revealAllContent, 3500);
});

window.addEventListener('load', revealAllContent);
