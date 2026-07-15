/*
 * Envoir hero visual — an illustrative mesh-of-nodes with small encrypted
 * "packets" (MOTEs) hopping through a mixnet path toward an always-on node.
 * Pure canvas, no dependencies. Honest about being a simulation, not a
 * literal network graph (see caption in the markup).
 */
(function () {
  "use strict";

  var canvas = document.getElementById("mesh-canvas");
  if (!canvas || !canvas.getContext) return;

  var ctx = canvas.getContext("2d");
  var reduceMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  var W = 0, H = 0, DPR = Math.min(window.devicePixelRatio || 1, 2);
  var nodes = [];
  var packets = [];
  var running = false;
  var rafId = null;
  var lastTime = 0;

  var ACCENT_1 = [91, 157, 255];   // #5B9DFF
  var ACCENT_2 = [124, 92, 255];   // #7C5CFF

  function lerpColor(a, b, t) {
    return [
      Math.round(a[0] + (b[0] - a[0]) * t),
      Math.round(a[1] + (b[1] - a[1]) * t),
      Math.round(a[2] + (b[2] - a[2]) * t)
    ];
  }

  function rgba(c, a) {
    return "rgba(" + c[0] + "," + c[1] + "," + c[2] + "," + a + ")";
  }

  function isLight() {
    return document.documentElement.getAttribute("data-theme") === "light";
  }

  function resize() {
    var rect = canvas.parentElement.getBoundingClientRect();
    W = Math.max(1, Math.floor(rect.width));
    H = Math.max(1, Math.floor(rect.height));
    canvas.width = Math.floor(W * DPR);
    canvas.height = Math.floor(H * DPR);
    canvas.style.width = W + "px";
    canvas.style.height = H + "px";
    ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
    layoutNodes();
  }

  function layoutNodes() {
    var count = W < 420 ? 16 : (W < 720 ? 22 : 30);
    nodes = [];
    // one node is the "home" node — bigger, anchored near center-bottom
    var homeX = W * 0.5, homeY = H * 0.72;
    nodes.push({ x: homeX, y: homeY, vx: 0, vy: 0, home: true, r: 6.5, phase: Math.random() * Math.PI * 2 });

    for (var i = 1; i < count; i++) {
      nodes.push({
        x: Math.random() * W,
        y: Math.random() * H * 0.86,
        vx: (Math.random() - 0.5) * 0.10,
        vy: (Math.random() - 0.5) * 0.10,
        home: false,
        r: 2.2 + Math.random() * 1.6,
        phase: Math.random() * Math.PI * 2
      });
    }
  }

  function neighborLinks() {
    // connect each node to its ~2-3 nearest neighbors (cheap approx, small N)
    var links = [];
    var maxDist = Math.max(W, H) * 0.30;
    for (var i = 0; i < nodes.length; i++) {
      var dists = [];
      for (var j = 0; j < nodes.length; j++) {
        if (i === j) continue;
        var dx = nodes[i].x - nodes[j].x, dy = nodes[i].y - nodes[j].y;
        var d = Math.sqrt(dx * dx + dy * dy);
        if (d < maxDist) dists.push({ j: j, d: d });
      }
      dists.sort(function (a, b) { return a.d - b.d; });
      var take = Math.min(3, dists.length);
      for (var k = 0; k < take; k++) {
        var a = Math.min(i, dists[k].j), b = Math.max(i, dists[k].j);
        links.push(a + "-" + b);
      }
    }
    // dedupe
    var seen = {};
    var out = [];
    for (var m = 0; m < links.length; m++) {
      if (!seen[links[m]]) { seen[links[m]] = true; out.push(links[m]); }
    }
    return out.map(function (s) {
      var parts = s.split("-");
      return [parseInt(parts[0], 10), parseInt(parts[1], 10)];
    });
  }

  var links = [];
  var linkTimer = 0;

  function spawnPacket() {
    // pick a random non-home source, route through 2-3 intermediate hops, end at home
    var sourceCandidates = [];
    for (var i = 1; i < nodes.length; i++) sourceCandidates.push(i);
    if (!sourceCandidates.length) return;
    var src = sourceCandidates[Math.floor(Math.random() * sourceCandidates.length)];

    var hops = [src];
    var hopCount = 2 + Math.floor(Math.random() * 2); // 2-3 relay hops
    var used = { 0: true };
    used[src] = true;
    for (var h = 0; h < hopCount; h++) {
      var idx;
      var attempts = 0;
      do {
        idx = 1 + Math.floor(Math.random() * (nodes.length - 1));
        attempts++;
      } while (used[idx] && attempts < 10);
      used[idx] = true;
      hops.push(idx);
    }
    hops.push(0); // home node

    packets.push({
      hops: hops,
      seg: 0,
      t: 0,
      speed: 0.55 + Math.random() * 0.35, // segments per second
      color: Math.random() < 0.5 ? ACCENT_1 : ACCENT_2
    });
  }

  var spawnTimer = 0;
  var spawnEvery = 1.4;

  function step(dt) {
    // drift nodes gently, keep in bounds
    for (var i = 1; i < nodes.length; i++) {
      var n = nodes[i];
      n.x += n.vx * dt * 60;
      n.y += n.vy * dt * 60;
      if (n.x < 10 || n.x > W - 10) n.vx *= -1;
      if (n.y < 10 || n.y > H * 0.86) n.vy *= -1;
      n.x = Math.max(6, Math.min(W - 6, n.x));
      n.y = Math.max(6, Math.min(H * 0.9, n.y));
      n.phase += dt * 1.2;
    }

    linkTimer += dt;
    if (linkTimer > 1.6) { links = neighborLinks(); linkTimer = 0; }

    spawnTimer += dt;
    if (spawnTimer > spawnEvery && packets.length < 6) {
      spawnTimer = 0;
      spawnEvery = 0.9 + Math.random() * 1.2;
      spawnPacket();
    }

    for (var p = packets.length - 1; p >= 0; p--) {
      var pk = packets[p];
      pk.t += dt * pk.speed;
      if (pk.t >= 1) {
        pk.t = 0;
        pk.seg++;
        if (pk.seg >= pk.hops.length - 1) {
          packets.splice(p, 1);
          nodes[0].pulse = 1;
        }
      }
    }
    if (nodes[0].pulse) {
      nodes[0].pulse -= dt * 1.4;
      if (nodes[0].pulse < 0) nodes[0].pulse = 0;
    }
  }

  function draw() {
    ctx.clearRect(0, 0, W, H);
    var light = isLight();
    var lineColor = light ? "rgba(20,20,25,0.14)" : "rgba(238,241,247,0.14)";
    var dimLine = light ? "rgba(20,20,25,0.07)" : "rgba(238,241,247,0.07)";

    // links
    ctx.lineWidth = 1;
    for (var l = 0; l < links.length; l++) {
      var a = nodes[links[l][0]], b = nodes[links[l][1]];
      if (!a || !b) continue;
      ctx.strokeStyle = (a.home || b.home) ? lineColor : dimLine;
      ctx.beginPath();
      ctx.moveTo(a.x, a.y);
      ctx.lineTo(b.x, b.y);
      ctx.stroke();
    }

    // nodes
    for (var i = 0; i < nodes.length; i++) {
      var n = nodes[i];
      var glow = n.home ? (0.5 + Math.sin(n.phase) * 0.15 + (n.pulse || 0) * 0.6) : (0.35 + Math.sin(n.phase) * 0.12);
      var col = n.home ? ACCENT_2 : lerpColor(ACCENT_1, ACCENT_2, 0.3);
      if (n.home && n.pulse) {
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.r + 10 * n.pulse, 0, Math.PI * 2);
        ctx.strokeStyle = rgba(ACCENT_1, 0.35 * n.pulse);
        ctx.lineWidth = 1.5;
        ctx.stroke();
      }
      ctx.beginPath();
      ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
      ctx.fillStyle = rgba(col, glow);
      ctx.fill();
      if (n.home) {
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.r + 4, 0, Math.PI * 2);
        ctx.strokeStyle = rgba(ACCENT_1, 0.4);
        ctx.lineWidth = 1;
        ctx.stroke();
      }
    }

    // packets: draw a short onion-fading trail then the head dot
    for (var p = 0; p < packets.length; p++) {
      var pk = packets[p];
      var from = nodes[pk.hops[pk.seg]];
      var to = nodes[pk.hops[pk.seg + 1]];
      if (!from || !to) continue;
      var x = from.x + (to.x - from.x) * pk.t;
      var y = from.y + (to.y - from.y) * pk.t;

      // trail
      var trailLen = 5;
      for (var tI = trailLen; tI >= 0; tI--) {
        var tt = Math.max(0, pk.t - tI * 0.05);
        var tx = from.x + (to.x - from.x) * tt;
        var ty = from.y + (to.y - from.y) * tt;
        var alpha = (1 - tI / trailLen) * 0.5;
        ctx.beginPath();
        ctx.arc(tx, ty, 2.4 * (1 - tI / (trailLen + 2)), 0, Math.PI * 2);
        ctx.fillStyle = rgba(pk.color, alpha);
        ctx.fill();
      }

      ctx.beginPath();
      ctx.arc(x, y, 2.6, 0, Math.PI * 2);
      ctx.fillStyle = rgba(pk.color, 0.95);
      ctx.shadowBlur = 8;
      ctx.shadowColor = rgba(pk.color, 0.8);
      ctx.fill();
      ctx.shadowBlur = 0;
    }
  }

  function drawStatic() {
    // reduced-motion: single calm frame, no animation loop
    links = neighborLinks();
    ctx.clearRect(0, 0, W, H);
    var light = isLight();
    var lineColor = light ? "rgba(20,20,25,0.16)" : "rgba(238,241,247,0.16)";
    ctx.lineWidth = 1;
    ctx.strokeStyle = lineColor;
    for (var l = 0; l < links.length; l++) {
      var a = nodes[links[l][0]], b = nodes[links[l][1]];
      if (!a || !b) continue;
      ctx.beginPath();
      ctx.moveTo(a.x, a.y);
      ctx.lineTo(b.x, b.y);
      ctx.stroke();
    }
    for (var i = 0; i < nodes.length; i++) {
      var n = nodes[i];
      var col = n.home ? ACCENT_2 : ACCENT_1;
      ctx.beginPath();
      ctx.arc(n.x, n.y, n.home ? n.r + 2 : n.r, 0, Math.PI * 2);
      ctx.fillStyle = rgba(col, n.home ? 0.9 : 0.55);
      ctx.fill();
    }
  }

  function loop(ts) {
    if (!running) return;
    var dt = lastTime ? Math.min(0.05, (ts - lastTime) / 1000) : 0.016;
    lastTime = ts;
    step(dt);
    draw();
    rafId = requestAnimationFrame(loop);
  }

  function start() {
    if (running) return;
    running = true;
    lastTime = 0;
    rafId = requestAnimationFrame(loop);
  }

  function stop() {
    running = false;
    if (rafId) cancelAnimationFrame(rafId);
    rafId = null;
  }

  function init() {
    resize();
    if (reduceMotion) {
      drawStatic();
      return;
    }
    links = neighborLinks();

    // pause when off-screen or tab hidden — a good citizen, not a battery drain
    if ("IntersectionObserver" in window) {
      var io = new IntersectionObserver(function (entries) {
        entries.forEach(function (e) { e.isIntersecting ? start() : stop(); });
      }, { threshold: 0.05 });
      io.observe(canvas);
    } else {
      start();
    }
    document.addEventListener("visibilitychange", function () {
      if (document.hidden) stop(); else if (!reduceMotion) start();
    });
  }

  var resizeTimer;
  window.addEventListener("resize", function () {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(function () {
      resize();
      if (reduceMotion) drawStatic();
    }, 120);
  });

  // repaint (static mode) if theme toggles
  window.addEventListener("envoir:theme-changed", function () {
    if (reduceMotion) drawStatic();
  });

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
