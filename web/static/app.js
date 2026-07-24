const $ = (id) => document.getElementById(id);
const canvas = $("networkCanvas");
const ctx = canvas.getContext("2d");
const comparisonCanvas = $("comparisonChart");
const timelineCanvas = $("timelineChart");
const costCanvas = $("costChart");

const baseline = {
  flooding: { label: "AODV-like", pdr: 87.61, delay: 8.61, throughput: 114.83, overhead: 11.82, blocked: 0 },
  clustered: { label: "Clustered", pdr: 92.77, delay: 7.84, throughput: 121.59, overhead: 7.12, blocked: 0 },
  secure: { label: "Secure", pdr: 92.01, delay: 9.53, throughput: 102.54, overhead: 7.27, blocked: 958 },
};

let state = { running: false, time: 0, frame: 0, vehicles: [], links: [], metrics: { ...baseline.secure }, timeline: [] };

function seeded(seed) {
  let value = seed >>> 0;
  return () => ((value = (value * 1664525 + 1013904223) >>> 0) / 4294967296);
}

function createVehicles(count) {
  const random = seeded(20260724 + count);
  const vehicles = [];
  for (let i = 0; i < count; i++) {
    const horizontal = i % 3 !== 2;
    const lane = i % 2;
    vehicles.push({
      id: i,
      x: horizontal ? 70 + random() * 1360 : 520 + lane * 390,
      y: horizontal ? 490 + lane * 390 : 70 + random() * 1360,
      vx: horizontal ? (i % 4 < 2 ? 1 : -1) * (1.5 + random() * 2.2) : 0,
      vy: horizontal ? 0 : (i % 4 < 2 ? 1 : -1) * (1.5 + random() * 2.2),
      malicious: i === 3 || i === 11 || (i > 14 && i % 9 === 0),
      cluster: 0,
    });
  }
  return vehicles;
}

const rsus = [
  { x: 360, y: 490, label: "RSU-A" }, { x: 1130, y: 880, label: "RSU-B" },
  { x: 520, y: 360, label: "RSU-C" }, { x: 910, y: 1130, label: "RSU-D" },
];
const clusterColors = ["#4de2ef", "#3d7eff", "#b8f536", "#bd7cff"];

function reset() {
  state.running = false;
  state.time = 0;
  state.frame = 0;
  state.vehicles = createVehicles(Number($("vehicleCount").value));
  state.timeline = [];
  $("clock").textContent = "00.0s";
  $("runState").textContent = "READY";
  $("runButton").innerHTML = "Run simulation <span>→</span>";
  $("eventText").textContent = "Configure the network and start the simulation.";
  calculateLinks();
  computeMetrics();
  drawNetwork();
  drawAllCharts();
}

function updatePositions() {
  for (const v of state.vehicles) {
    v.x += v.vx;
    v.y += v.vy;
    if (v.x < 45 || v.x > 1455) { v.vx *= -1; v.x = Math.max(45, Math.min(1455, v.x)); }
    if (v.y < 45 || v.y > 1455) { v.vy *= -1; v.y = Math.max(45, Math.min(1455, v.y)); }
  }
}

function calculateLinks() {
  const range = Number($("range").value);
  state.links = [];
  for (let i = 0; i < state.vehicles.length; i++) {
    const v = state.vehicles[i];
    let nearest = 0;
    let nearestDistance = Infinity;
    rsus.forEach((r, index) => {
      const d = Math.hypot(v.x - r.x, v.y - r.y);
      if (d < nearestDistance) { nearestDistance = d; nearest = index; }
    });
    v.cluster = nearest;
    for (let j = i + 1; j < state.vehicles.length; j++) {
      const other = state.vehicles[j];
      if (Math.hypot(v.x - other.x, v.y - other.y) < range) state.links.push([i, j]);
    }
  }
}

function computeMetrics() {
  const protocol = $("protocol").value;
  const count = Number($("vehicleCount").value);
  const range = Number($("range").value);
  const threats = Number($("malicious").value);
  const base = baseline[protocol];
  const density = (count - 15) * 0.13;
  const coverage = (range - 390) * 0.018;
  const threatPenalty = protocol === "secure" ? threats * 0.015 : threats * 0.13;
  const noise = Math.sin(state.time * 1.7 + count) * 0.28;
  state.metrics = {
    pdr: Math.max(60, Math.min(99.4, base.pdr + coverage - density - threatPenalty + noise)),
    delay: Math.max(2, base.delay + density * .5 - coverage * .12 + threats * (protocol === "secure" ? .022 : .045)),
    throughput: Math.max(20, base.throughput + coverage * 1.1 - density * 1.6 - threats * (protocol === "secure" ? .32 : .12)),
    overhead: Math.max(2, base.overhead + density * .22 - coverage * .04 + (protocol === "flooding" ? count * .025 : 0)),
    blocked: protocol === "secure" ? Math.round(6400 * threats / 100) : 0,
  };
  updateMetrics();
}

function updateMetrics() {
  const m = state.metrics;
  $("pdr").innerHTML = `${m.pdr.toFixed(2)}<span>%</span>`;
  $("delay").innerHTML = `${m.delay.toFixed(2)}<span>ms</span>`;
  $("throughput").innerHTML = `${m.throughput.toFixed(2)}<span>kbps</span>`;
  $("overhead").innerHTML = `${m.overhead.toFixed(2)}<span>x</span>`;
  $("blocked").textContent = m.blocked;
  $("summaryText").textContent = $("protocol").value === "secure"
    ? `Secure clustering blocked ${m.blocked} threats while delivering ${m.pdr.toFixed(2)}% of trusted packets.`
    : `${baseline[$("protocol").value].label} delivered ${m.pdr.toFixed(2)}% of offered packets.`;
}

function project(x, y) {
  return { x: x / 1500 * canvas.width, y: y / 1500 * canvas.height };
}

function drawNetwork() {
  const w = canvas.width, h = canvas.height;
  ctx.clearRect(0, 0, w, h);
  ctx.fillStyle = "#091524"; ctx.fillRect(0, 0, w, h);
  ctx.strokeStyle = "#16263a"; ctx.lineWidth = 1;
  for (let x = 0; x <= w; x += 55) { ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, h); ctx.stroke(); }
  for (let y = 0; y <= h; y += 55) { ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke(); }

  const roads = [
    [0, 205, w, 205], [0, 390, w, 390], [382, 0, 382, h], [667, 0, 667, h],
  ];
  ctx.lineWidth = 54; ctx.strokeStyle = "#111f30";
  roads.forEach(([x1, y1, x2, y2]) => { ctx.beginPath(); ctx.moveTo(x1, y1); ctx.lineTo(x2, y2); ctx.stroke(); });
  ctx.setLineDash([17, 17]); ctx.lineWidth = 1; ctx.strokeStyle = "#516074";
  roads.forEach(([x1, y1, x2, y2]) => { ctx.beginPath(); ctx.moveTo(x1, y1); ctx.lineTo(x2, y2); ctx.stroke(); });
  ctx.setLineDash([]);

  ctx.lineWidth = 1;
  state.links.slice(0, 120).forEach(([a, b]) => {
    const p1 = project(state.vehicles[a].x, state.vehicles[a].y);
    const p2 = project(state.vehicles[b].x, state.vehicles[b].y);
    ctx.strokeStyle = "rgba(77,226,239,.16)";
    ctx.beginPath(); ctx.moveTo(p1.x, p1.y); ctx.lineTo(p2.x, p2.y); ctx.stroke();
  });

  rsus.forEach((r, i) => {
    const p = project(r.x, r.y);
    ctx.strokeStyle = `${clusterColors[i]}40`; ctx.lineWidth = 1;
    ctx.beginPath(); ctx.arc(p.x, p.y, Number($("range").value) / 1500 * w, 0, Math.PI * 2); ctx.stroke();
    ctx.fillStyle = clusterColors[i]; ctx.fillRect(p.x - 8, p.y - 8, 16, 16);
    ctx.fillStyle = "#c7d1dd"; ctx.font = "11px DM Mono"; ctx.fillText(r.label, p.x + 12, p.y + 4);
  });

  state.vehicles.forEach((v) => {
    const p = project(v.x, v.y);
    ctx.save(); ctx.translate(p.x, p.y);
    ctx.fillStyle = v.malicious ? "#ff7452" : clusterColors[v.cluster];
    ctx.shadowBlur = 12; ctx.shadowColor = ctx.fillStyle;
    ctx.beginPath(); ctx.arc(0, 0, v.malicious ? 6 : 5, 0, Math.PI * 2); ctx.fill();
    ctx.shadowBlur = 0; ctx.fillStyle = "#d9e3ed"; ctx.font = "9px DM Mono"; ctx.fillText(`V${v.id}`, 8, -8);
    ctx.restore();
  });
}

function drawAxes(context, w, h, labels) {
  const pad = { l: 48, r: 20, t: 18, b: 42 };
  context.strokeStyle = "#34455a"; context.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = pad.t + (h - pad.t - pad.b) * i / 4;
    context.beginPath(); context.moveTo(pad.l, y); context.lineTo(w - pad.r, y); context.stroke();
  }
  context.fillStyle = "#7c8b9e"; context.font = "11px DM Mono";
  labels.forEach((label, i) => {
    const x = pad.l + (w - pad.l - pad.r) * (i + .5) / labels.length;
    context.textAlign = "center"; context.fillText(label, x, h - 15);
  });
  return pad;
}

function drawComparison() {
  const c = comparisonCanvas.getContext("2d"), w = comparisonCanvas.width, h = comparisonCanvas.height;
  c.clearRect(0, 0, w, h);
  const labels = Object.values(baseline).map(v => v.label);
  const pad = drawAxes(c, w, h, labels);
  const group = (w - pad.l - pad.r) / 3;
  Object.values(baseline).forEach((v, i) => {
    const selected = Object.keys(baseline)[i] === $("protocol").value;
    const x = pad.l + i * group + group * .2;
    const maxH = h - pad.t - pad.b;
    c.fillStyle = selected ? "#b8f536" : "#3d7eff";
    c.fillRect(x, pad.t + maxH * (1 - v.pdr / 100), group * .25, maxH * v.pdr / 100);
    c.fillStyle = selected ? "#4de2ef" : "#566b86";
    c.fillRect(x + group * .31, pad.t + maxH * (1 - v.throughput / 140), group * .25, maxH * v.throughput / 140);
  });
  c.textAlign = "left"; c.fillStyle = "#b8f536"; c.fillText("■ PDR", 55, 13);
  c.fillStyle = "#4de2ef"; c.fillText("■ Throughput", 125, 13);
}

function drawLineChart(canvasEl, values, color, maxValue, suffix) {
  const c = canvasEl.getContext("2d"), w = canvasEl.width, h = canvasEl.height;
  c.clearRect(0, 0, w, h);
  const labels = ["0s", "5s", "10s", "15s", "20s"];
  const pad = drawAxes(c, w, h, labels);
  if (!values.length) return;
  c.strokeStyle = color; c.lineWidth = 3; c.beginPath();
  values.forEach((v, i) => {
    const x = pad.l + (w - pad.l - pad.r) * i / Math.max(1, values.length - 1);
    const y = pad.t + (h - pad.t - pad.b) * (1 - v / maxValue);
    i ? c.lineTo(x, y) : c.moveTo(x, y);
  });
  c.stroke();
  c.fillStyle = color; c.font = "11px DM Mono"; c.textAlign = "right";
  c.fillText(`${values.at(-1).toFixed(1)}${suffix}`, w - 22, 14);
}

function drawCost() {
  const values = state.timeline.length ? state.timeline.map(v => v.overhead) : [6.8, 7.1, 7.4, 7.2, 7.27];
  drawLineChart(costCanvas, values, "#ff7452", 15, "x");
}

function drawAllCharts() {
  drawComparison();
  const pdrValues = state.timeline.length ? state.timeline.map(v => v.pdr) : [88, 90, 91.5, 91.9, 92.01];
  drawLineChart(timelineCanvas, pdrValues, "#4de2ef", 100, "%");
  drawCost();
}

function animate() {
  if (!state.running) return;
  state.frame++;
  if (state.frame % 3 === 0) {
    state.time = Math.min(20, state.time + .1);
    updatePositions();
    calculateLinks();
    computeMetrics();
    if (state.frame % 30 === 0) {
      state.timeline.push({ pdr: state.metrics.pdr, overhead: state.metrics.overhead });
      drawAllCharts();
      const messages = [
        "RSU-A assigned a vehicle to cluster 1.",
        "Multi-hop safety packet delivered successfully.",
        $("protocol").value === "secure" ? "Trusted authority rejected a modified packet." : "Route request propagated across nearby nodes.",
        "Wireless links updated after vehicle movement.",
      ];
      $("eventText").textContent = messages[(state.frame / 30) % messages.length | 0];
    }
    $("clock").textContent = `${state.time.toFixed(1).padStart(4, "0")}s`;
    drawNetwork();
  }
  if (state.time >= 20) {
    state.running = false;
    $("runState").textContent = "COMPLETE";
    $("runButton").innerHTML = "Run again <span>↻</span>";
    $("eventText").textContent = `Run complete: ${state.metrics.pdr.toFixed(2)}% PDR and ${state.metrics.blocked} threats blocked.`;
    drawAllCharts();
    $("results").scrollIntoView({ behavior: "smooth", block: "start" });
    return;
  }
  requestAnimationFrame(animate);
}

function start() {
  if (state.running) {
    state.running = false;
    $("runState").textContent = "PAUSED";
    $("runButton").innerHTML = "Resume simulation <span>→</span>";
    return;
  }
  if (state.time >= 20) reset();
  state.running = true;
  $("runState").textContent = "RUNNING";
  $("runButton").innerHTML = "Pause simulation <span>Ⅱ</span>";
  $("eventText").textContent = "Simulation started. Discovering active wireless routes…";
  requestAnimationFrame(animate);
}

function downloadCsv() {
  const m = state.metrics;
  const csv = [
    "protocol,vehicles,radio_range_m,malicious_percent,pdr_percent,delay_ms,throughput_kbps,overhead_ratio,threats_blocked",
    `${baseline[$("protocol").value].label},${$("vehicleCount").value},${$("range").value},${$("malicious").value},${m.pdr.toFixed(3)},${m.delay.toFixed(3)},${m.throughput.toFixed(3)},${m.overhead.toFixed(3)},${m.blocked}`,
  ].join("\n");
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
  a.download = "vanet-cloud-results.csv";
  a.click();
  URL.revokeObjectURL(a.href);
}

$("runButton").addEventListener("click", start);
$("resetButton").addEventListener("click", reset);
$("downloadButton").addEventListener("click", downloadCsv);
["protocol", "vehicleCount", "range", "malicious"].forEach(id => {
  $(id).addEventListener("input", () => {
    $("vehicleValue").textContent = $("vehicleCount").value;
    $("heroVehicles").textContent = $("vehicleCount").value;
    $("rangeValue").textContent = `${$("range").value} m`;
    $("maliciousValue").textContent = `${$("malicious").value}%`;
    reset();
  });
});

reset();
