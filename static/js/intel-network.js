/**
 * BIGIL Intelligence Network Graph
 * Renders entity relationship nodes on canvas elements.
 */
(function () {
  'use strict';

  function initIntelGraph(canvasId, nodes, edges) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    let W, H;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);

    function resize() {
      const rect = canvas.parentElement.getBoundingClientRect();
      W = rect.width;
      H = rect.height || 200;
      canvas.width = W * dpr;
      canvas.height = H * dpr;
      canvas.style.width = W + 'px';
      canvas.style.height = H + 'px';
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    }

    resize();
    window.addEventListener('resize', resize);

    const graphNodes = (nodes || []).slice(0, 12).map((n, i) => {
      const angle = (i / Math.max(nodes.length, 1)) * Math.PI * 2;
      const r = Math.min(W, H) * 0.32;
      return {
        id: n.value || n.id || String(i),
        label: (n.value || n.id || 'node').slice(0, 18),
        count: n.count || 1,
        x: W / 2 + Math.cos(angle) * r,
        y: H / 2 + Math.sin(angle) * r,
        vx: 0, vy: 0,
        type: n.type || 'ip'
      };
    });

    // Hub node
    graphNodes.unshift({
      id: 'hub', label: 'BIGIL', count: 0,
      x: W / 2, y: H / 2, vx: 0, vy: 0, type: 'hub', fixed: true
    });

    const graphEdges = (edges || []).slice(0, 8).map(e => ({
      source: e.source, target: e.target, weight: e.weight || 1
    }));

    // Connect orphans to hub
    graphNodes.slice(1).forEach(n => {
      if (!graphEdges.some(e => e.source === n.id || e.target === n.id)) {
        graphEdges.push({ source: 'hub', target: n.id, weight: 1 });
      }
    });

    let frame = 0;
    let hidden = false;
    document.addEventListener('visibilitychange', () => { hidden = document.hidden; });

    function findNode(id) {
      return graphNodes.find(n => n.id === id);
    }

    function draw() {
      if (hidden) { requestAnimationFrame(draw); return; }
      frame++;
      ctx.clearRect(0, 0, W, H);

      // Edges
      graphEdges.forEach(e => {
        const a = findNode(e.source) || findNode('hub');
        const b = findNode(e.target);
        if (!a || !b) return;
        const pulse = 0.15 + 0.1 * Math.sin(frame * 0.03 + e.weight);
        ctx.beginPath();
        ctx.moveTo(a.x, a.y);
        ctx.lineTo(b.x, b.y);
        ctx.strokeStyle = `rgba(14, 165, 233, ${pulse})`;
        ctx.lineWidth = 1;
        ctx.stroke();

        // Data flow dot
        const t = (frame * 0.008 + e.weight * 0.1) % 1;
        const dx = a.x + (b.x - a.x) * t;
        const dy = a.y + (b.y - a.y) * t;
        ctx.beginPath();
        ctx.arc(dx, dy, 2, 0, Math.PI * 2);
        ctx.fillStyle = 'rgba(34, 211, 238, 0.8)';
        ctx.fill();
      });

      // Nodes
      graphNodes.forEach(n => {
        const r = n.type === 'hub' ? 14 : 6 + Math.min(n.count, 5);
        const glow = n.type === 'hub' ? 20 : 10;

        const grad = ctx.createRadialGradient(n.x, n.y, 0, n.x, n.y, glow);
        grad.addColorStop(0, n.type === 'hub' ? 'rgba(99,102,241,0.4)' : 'rgba(14,165,233,0.3)');
        grad.addColorStop(1, 'transparent');
        ctx.beginPath();
        ctx.arc(n.x, n.y, glow, 0, Math.PI * 2);
        ctx.fillStyle = grad;
        ctx.fill();

        ctx.beginPath();
        ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
        ctx.fillStyle = n.type === 'hub' ? '#6366F1' : '#0EA5E9';
        ctx.fill();
        ctx.strokeStyle = 'rgba(34, 211, 238, 0.6)';
        ctx.lineWidth = 1;
        ctx.stroke();

        if (n.type === 'hub' || n.count > 2) {
          ctx.fillStyle = 'rgba(226, 232, 240, 0.85)';
          ctx.font = '9px Inter, sans-serif';
          ctx.textAlign = 'center';
          ctx.fillText(n.label, n.x, n.y + r + 12);
        }
      });

      requestAnimationFrame(draw);
    }

    draw();
  }

  window.BIGILIntelGraph = { init: initIntelGraph };

  document.addEventListener('DOMContentLoaded', () => {
    const el = document.getElementById('intel-network-canvas');
    if (el && el.dataset.nodes) {
      try {
        const nodes = JSON.parse(el.dataset.nodes);
        const edges = JSON.parse(el.dataset.edges || '[]');
        initIntelGraph('intel-network-canvas', nodes, edges);
      } catch (e) { /* ignore */ }
    }
  });
})();
