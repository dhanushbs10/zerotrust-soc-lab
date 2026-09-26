/* Live trust-topology overlay
   ------------------------------------------------------------------
   Appended to the Sentinel console. Draws the verified paths as actual curves
   between the node cards the base renderer already produces, and animates them
   while a collection job is running.

   Why this is a separate file rather than part of renderGraph
   ----------------------------------------------------------
   renderGraph rebuilds the zone columns from scratch every refresh. Drawing
   edges needs the *laid out* geometry of those columns, which only exists after
   the browser has reflowed them. Keeping the two apart means the geometry can
   be recomputed on resize, on font load and on scroll without re-rendering any
   data, and a failure here cannot take the topology list down with it.

   The honesty constraints are inherited from the base view and must not be
   weakened here:

     - an edge is drawn only for a pair the datapath confirmed as open, or that
       was permitted with no listener. A modelled-but-blocked pair is drawn
       dashed, grey, and only when the operator asks to see the deny matrix.
     - "open" means the datapath agreed. It does not mean the path is safe, and
       it says nothing about an actor already inside a permitted path.
     - elapsed time is shown because it is the measurement: a refused connection
       answers in 0-100ms, a dropped SYN is silent past 1000ms, and the cut is
       at 600ms. An edge that took 380ms and one that took 0ms are not the same
       observation.

   No network requests are made from here. The base refresh owns polling. */

(function () {
  'use strict';

  const SVG_NS = 'http://www.w3.org/2000/svg';
  const host = () => document.getElementById('graph');
  let lastSignature = '';
  let raf = null;

  /* An edge is identified by its endpoints and port, not by array index, so a
     re-render that reorders edges does not restart every animation. */
  const signatureOf = (e) => `${e.from}->${e.to}:${e.port}/${e.protocol || 'TCP'}`;

  function geometry() {
    const container = host();
    if (!container) return null;
    const base = container.getBoundingClientRect();
    if (!base.width) return null;

    const cards = new Map();
    container.querySelectorAll('.node-card[data-node]').forEach((card) => {
      const id = card.getAttribute('data-node');
      const r = card.getBoundingClientRect();
      cards.set(id, {
        left: r.left - base.left + container.scrollLeft,
        right: r.right - base.left + container.scrollLeft,
        top: r.top - base.top + container.scrollTop,
        bottom: r.bottom - base.top + container.scrollTop,
        cx: r.left - base.left + container.scrollLeft + r.width / 2,
        cy: r.top - base.top + container.scrollTop + r.height / 2,
      });
    });
    return { container, base, cards };
  }

  /* Draws from source to destination, respecting the edge's direction.

     An earlier version always drew left to right, which silently reversed every
     edge whose destination sat to the left of its source -- and in this lab most
     of them do, because the observe zone is the rightmost column and it is the
     source of four of the six open edges. A reachability map whose arrows point
     the wrong way is worse than no arrows, because it looks authoritative.

     So: source side is chosen by direction, and the control points are pushed
     along the travel axis so a long cross-zone hop arcs visibly instead of
     running flat through the middle of the map. */
  function curve(src, dst) {
    const rightward = dst.cx >= src.cx;
    const startX = rightward ? src.right : src.left;
    const endX = rightward ? dst.left : dst.right;
    const dx = Math.max(24, Math.abs(endX - startX) * 0.42);
    const c1 = rightward ? startX + dx : startX - dx;
    const c2 = rightward ? endX - dx : endX + dx;
    return {
      d: `M ${startX} ${src.cy} C ${c1} ${src.cy}, ${c2} ${dst.cy}, ${endX} ${dst.cy}`,
      rightward,
      tipX: endX,
      tipY: dst.cy,
    };
  }

  /* Same-zone hops are both cards in one column, stacked vertically. A cubic
     between them with horizontal control points runs straight down through the
     card between, so those get a lateral bow instead. */
  function curveSameColumn(src, dst) {
    const startY = dst.cy > src.cy ? src.bottom : src.top;
    const endY = dst.cy > src.cy ? dst.top : dst.bottom;
    const bow = Math.min(70, Math.max(38, Math.abs(startY - endY) * 0.42));
    return {
      d: `M ${src.cx} ${startY} C ${src.cx + bow} ${startY}, ${dst.cx + bow} ${endY}, ${dst.cx} ${endY}`,
      rightward: true,
      tipX: dst.cx,
      tipY: endY,
    };
  }

  function edgeEl(geom, cls, label) {
    const g = document.createElementNS(SVG_NS, 'g');
    g.setAttribute('class', `edge-overlay-group ${cls}`);

    const hit = document.createElementNS(SVG_NS, 'path');
    hit.setAttribute('d', geom.d);
    hit.setAttribute('class', 'edge-hit');
    g.appendChild(hit);

    const line = document.createElementNS(SVG_NS, 'path');
    line.setAttribute('d', geom.d);
    line.setAttribute('class', 'edge-stroke');
    g.appendChild(line);

    // Arrowhead at the destination, so direction is legible without hovering.
    const head = document.createElementNS(SVG_NS, 'path');
    const s = cls === 'blocked' ? 4 : 6;
    const dx = geom.rightward ? 1 : -1;
    head.setAttribute(
      'd',
      `M ${geom.tipX} ${geom.tipY} L ${geom.tipX - s * dx} ${geom.tipY - s * 0.62} L ${geom.tipX - s * dx} ${geom.tipY + s * 0.62} Z`
    );
    head.setAttribute('class', `edge-head ${cls}`);
    g.appendChild(head);

    if (label) {
      const mid = document.createElementNS(SVG_NS, 'text');
      mid.setAttribute('class', 'edge-label');
      mid.textContent = label;
      g.appendChild(mid);
    }
    g._path = geom.d;
    return g;
  }

  function positionLabels(groups) {
    groups.forEach((g) => {
      const mid = g.querySelector('.edge-label');
      if (!mid) return;
      const p = cubicAt(g._path, 0.5);
      mid.setAttribute('x', p.x);
      mid.setAttribute('y', p.y - 6);
    });
  }

  function cubicAt(d, t) {
    const nums = d.match(/-?\d+(\.\d+)?/g);
    if (!nums || nums.length < 8) return { x: 0, y: 0 };
    const [x0, y0, c1x, c1y, c2x, c2y, x1, y1] = nums.map(Number);
    const u = 1 - t;
    const a = u * u * u;
    const b = 3 * u * u * t;
    const c = 3 * u * t * t;
    const d2 = t * t * t;
    return {
      x: a * x0 + b * c1x + c * c2x + d2 * x1,
      y: a * y0 + b * c1y + c * c2y + d2 * y1,
    };
  }

  function draw() {
    raf = null;
    const geom = geometry();
    if (!geom) return;
    const { container, cards } = geom;

    let svg = container.querySelector('svg.edge-overlay');
    if (!svg) {
      svg = document.createElementNS(SVG_NS, 'svg');
      svg.setAttribute('class', 'edge-overlay');
      svg.setAttribute('aria-hidden', 'true');
      container.appendChild(svg);
    }
    svg.setAttribute('width', container.scrollWidth);
    svg.setAttribute('height', container.scrollHeight);
    svg.setAttribute('viewBox', `0 0 ${container.scrollWidth} ${container.scrollHeight}`);

    const graph = window.__SENTINEL_GRAPH__ || { edges: [], blockedPairs: [] };
    const showBlocked = document.getElementById('show-blocked');
    const wantBlocked = showBlocked && showBlocked.checked;

    const sig = [
      (graph.edges || []).map(signatureOf).join(','),
      wantBlocked ? (graph.blockedPairs || []).map(signatureOf).join(',') : '',
      container.scrollWidth,
    ].join('|');
    if (sig === lastSignature) return;
    lastSignature = sig;

    while (svg.firstChild) svg.removeChild(svg.firstChild);

    const groups = [];

    /* A hop between two cards in the same column is drawn as a lateral bow; one
       that crosses columns is drawn as a horizontal cubic in the direction the
       edge actually travels. */
    const shapeFor = (a, b) => (Math.abs(a.cx - b.cx) < 12 ? curveSameColumn(a, b) : curve(a, b));

    (graph.edges || []).forEach((e) => {
      const a = cards.get(e.from);
      const b = cards.get(e.to);
      if (!a || !b) return;                 // an edge to a node not on screen is not drawn, not faked
      const refused = Boolean(e.noListener);
      const g = edgeEl(shapeFor(a, b), refused ? 'refused' : 'open',
        `${e.port}${e.elapsedMs != null ? ` · ${e.elapsedMs}ms` : ''}`);
      g.setAttribute('data-edge', signatureOf(e));
      svg.appendChild(g);
      groups.push(g);
    });

    if (wantBlocked) {
      (graph.blockedPairs || []).forEach((p) => {
        const a = cards.get(p.from);
        const b = cards.get(p.to);
        if (!a || !b) return;
        const g = edgeEl(shapeFor(a, b), 'blocked', `${p.port} DENIED`);
        g.setAttribute('data-edge', signatureOf(p));
        svg.appendChild(g);
      });
    }

    positionLabels(groups);
  }

  function schedule() {
    if (raf) return;
    raf = requestAnimationFrame(draw);
  }

  /* The base renderer replaces #graph wholesale, so the signature is reset and a
     redraw forced. Without this the overlay would keep the previous run's
     geometry against a freshly laid out map and sit visibly offset from it. */
  function invalidate() {
    lastSignature = '';
    schedule();
  }

  function setLive(on) {
    const container = host();
    if (container) container.classList.toggle('is-live', Boolean(on));
    document.body.classList.toggle('graph-live', Boolean(on));
  }

  /* Rebuilt on every poll while a job runs, so this fires often. Cheap: it is a
     single rect read per card and a signature comparison. */
  function onRefresh(graph) {
    if (graph) window.__SENTINEL_GRAPH__ = graph;
    invalidate();
  }

  window.SentinelGraph = { invalidate, schedule, setLive, onRefresh };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      const toggle = document.getElementById('show-blocked');
      if (toggle) toggle.addEventListener('change', invalidate);
      window.addEventListener('resize', invalidate);
    });
  } else {
    const toggle = document.getElementById('show-blocked');
    if (toggle) toggle.addEventListener('change', invalidate);
    window.addEventListener('resize', invalidate);
  }
})();
