/* PhishLens dashboard logic */
"use strict";

/* ---------------- boot sequence ---------------- */
const BOOT_LINES = [
  "> initializing phishlens v0.1.0 ...",
  "> loading detection modules [spf/dkim/dmarc] ... OK",
  "> loading homoglyph tables (cyrillic/greek) ... OK",
  "> calibrating 3d forensics renderer ... OK",
  "> ready. awaiting target.",
];
(function boot() {
  const term = document.getElementById("boot-term");
  const boot = document.getElementById("boot");
  let i = 0;
  term.innerHTML = '<span class="cursor"></span>';
  const cursor = term.querySelector(".cursor");
  function next() {
    if (i >= BOOT_LINES.length) {
      setTimeout(() => boot.classList.add("done"), 350);
      return;
    }
    const div = document.createElement("div");
    div.textContent = BOOT_LINES[i++];
    term.insertBefore(div, cursor);
    setTimeout(next, 260);
  }
  setTimeout(next, 300);
})();

/* ---------------- particle background ---------------- */
(function particles() {
  const c = document.getElementById("particles");
  const ctx = c.getContext("2d");
  let W, H, pts = [];
  function resize() {
    W = c.width = innerWidth; H = c.height = innerHeight;
  }
  resize(); addEventListener("resize", resize);
  for (let i = 0; i < 90; i++) {
    pts.push({ x: Math.random() * innerWidth, y: Math.random() * innerHeight,
               vx: (Math.random() - .5) * .3, vy: (Math.random() - .5) * .3,
               r: Math.random() * 1.8 + .4,
               col: Math.random() < .85 ? "0,229,255" : "255,45,120" });
  }
  (function tick() {
    ctx.clearRect(0, 0, W, H);
    for (const p of pts) {
      p.x += p.vx; p.y += p.vy;
      if (p.x < 0 || p.x > W) p.vx *= -1;
      if (p.y < 0 || p.y > H) p.vy *= -1;
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, 7);
      ctx.fillStyle = `rgba(${p.col},0.5)`;
      ctx.fill();
    }
    requestAnimationFrame(tick);
  })();
})();

/* ---------------- state + api ---------------- */
const statusEl = document.getElementById("status");
const resultsEl = document.getElementById("results");

function setStatus(msg, isErr) {
  statusEl.textContent = msg;
  statusEl.classList.toggle("err", !!isErr);
}

async function loadReport(promise, label) {
  setStatus("analyzing " + label + " ...");
  try {
    const res = await promise;
    if (!res.ok) throw new Error((await res.json()).detail || res.statusText);
    render(await res.json());
    setStatus("analysis complete: " + label);
  } catch (e) {
    setStatus("error: " + e.message, true);
  }
}

document.querySelectorAll("#demos button").forEach(b =>
  b.addEventListener("click", () =>
    loadReport(fetch("/api/demo/" + b.dataset.demo), b.dataset.demo + ".eml")));

const dz = document.getElementById("dropzone");
const fi = document.getElementById("file-input");
dz.addEventListener("click", () => fi.click());
dz.addEventListener("dragover", e => { e.preventDefault(); dz.classList.add("over"); });
dz.addEventListener("dragleave", () => dz.classList.remove("over"));
dz.addEventListener("drop", e => {
  e.preventDefault(); dz.classList.remove("over");
  if (e.dataTransfer.files.length) upload(e.dataTransfer.files[0]);
});
fi.addEventListener("change", () => { if (fi.files.length) upload(fi.files[0]); });

function upload(file) {
  const fd = new FormData();
  fd.append("file", file);
  loadReport(fetch("/api/analyze", { method: "POST", body: fd }), file.name);
}

/* ---------------- render ---------------- */
function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"]/g, c =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

function render(r) {
  resultsEl.classList.add("show");

  // meta
  const m = r.meta;
  document.getElementById("meta").innerHTML =
    `<b>SUBJECT</b> ${esc(m.subject)}<br><b>FROM</b> ${esc(m.from)}<br>` +
    `<b>DATE</b> ${esc(m.date || "—")}<br><b>HOPS</b> ${r.received_chain.length}`;

  // dial
  const score = r.verdict.score;
  const arc = document.getElementById("dial-arc");
  const colors = { Critical: "#ff2d78", High: "#ff2d78", Suspicious: "#ffb300", Low: "#00e5ff", Clean: "#00e676" };
  const col = colors[r.verdict.label] || "#00e5ff";
  arc.style.stroke = col; arc.style.color = col;
  requestAnimationFrame(() => { arc.style.strokeDashoffset = 283 - (283 * score / 100); });
  const num = document.getElementById("dial-num");
  const t0 = performance.now();
  (function count(t) {
    const p = Math.min(1, (t - t0) / 1400);
    num.textContent = Math.round(score * (1 - Math.pow(1 - p, 3)));
    if (p < 1) requestAnimationFrame(count);
  })(t0);
  const lbl = document.getElementById("verdict-label");
  lbl.textContent = r.verdict.label.toUpperCase();
  lbl.style.color = col; lbl.style.textShadow = `0 0 16px ${col}`;
  document.getElementById("verdict-score").textContent =
    `${r.verdict.reasons.length} indicator(s)`;

  // auth badges
  const auth = r.authentication;
  const cls = { pass: "pass", fail: "fail", softfail: "warn", none: "warn",
                neutral: "info", unavailable: "na" };
  document.getElementById("auth").innerHTML = ["spf", "dkim", "dmarc"].map(k => {
    const a = auth[k] || { status: "na", detail: "" };
    return `<div class="auth-badge ${cls[a.status] || "na"}">
      <div class="name">${k.toUpperCase()}</div>
      <div class="st">${esc(a.status.toUpperCase())}</div>
      <div class="st" style="opacity:.7;font-size:10px;margin-top:6px">${esc(a.detail.slice(0, 90))}</div>
    </div>`;
  }).join("");

  // reasons
  document.getElementById("reasons").innerHTML =
    r.verdict.reasons.map(x => `<div class="reason">${esc(x)}</div>`).join("");

  // urls
  const tb = document.querySelector("#urls tbody");
  tb.innerHTML = r.urls.length ? r.urls.map(u => {
    const chips = u.flags.map(f => {
      const c = ["ip_literal", "display_mismatch", "punycode", "at_trick"].includes(f) ? "crit"
              : ["shortener", "suspicious_tld"].includes(f) ? "warn" : "info";
      return `<span class="chip ${c}">${esc(f)}</span>`;
    }).join("") || '<span class="chip info">clean</span>';
    return `<tr><td class="mono">${esc(u.url)}${u.display_text ? `<br><span style="color:#7b8aa5">shown as: ${esc(u.display_text)}</span>` : ""}${u.note ? `<br><span style="color:#ffb300">${esc(u.note)}</span>` : ""}</td><td>${chips}</td></tr>`;
  }).join("") : `<tr><td colspan="2" style="color:#7b8aa5">no URLs found in body</td></tr>`;

  // raw headers with highlights
  const flagHosts = new Set();
  r.received_chain.forEach(h => { if (h.anomalies.length) { flagHosts.add(h.from_host); flagHosts.add(h.by_host); } });
  const dom = (r.domain_analysis && r.domain_analysis.domain) || "";
  const lines = r.raw_headers.split("\n").map(line => {
    const l = line.toLowerCase();
    let cls2 = "";
    if (l.includes("unknown") || l.includes("reply-to")) cls2 = "hl";
    for (const hh of flagHosts) { if (hh && l.includes(hh.toLowerCase())) cls2 = "hop-hl"; }
    if (dom && l.includes(dom.toLowerCase()) && dom.length > 3) cls2 = cls2 || "hl";
    return cls2 ? `<span class="${cls2}">${esc(line)}</span>` : esc(line);
  });
  document.getElementById("raw-headers").innerHTML = lines.join("\n");

  drawHops(r.received_chain);
  document.getElementById("results").scrollIntoView({ behavior: "smooth", block: "start" });
}

/* ---------------- three.js hop chain ---------------- */
let renderer, scene, camera, hopGroup, pulseNodes = [], raf = null;

function labelSprite(text, color) {
  const cv = document.createElement("canvas");
  cv.width = 512; cv.height = 96;
  const g = cv.getContext("2d");
  g.font = "28px monospace"; g.textAlign = "center";
  g.shadowColor = color; g.shadowBlur = 14; g.fillStyle = color;
  const short = text.length > 34 ? text.slice(0, 33) + "…" : text;
  g.fillText(short, 256, 58);
  const tex = new THREE.CanvasTexture(cv);
  const sp = new THREE.Sprite(new THREE.SpriteMaterial({ map: tex, transparent: true, depthTest: false }));
  sp.scale.set(7.5, 1.4, 1);
  return sp;
}

function drawHops(hops) {
  const canvas = document.getElementById("hop3d");
  if (!window.THREE) { canvas.outerHTML = "<p style='color:#7b8aa5'>3D unavailable (CDN blocked)</p>"; return; }

  if (!renderer) {
    renderer = new THREE.WebGLRenderer({ canvas, alpha: true, antialias: true });
    scene = new THREE.Scene();
    scene.fog = new THREE.FogExp2(0x05070f, 0.028);
    camera = new THREE.PerspectiveCamera(55, 2, 0.1, 200);
    camera.position.set(0, 5.5, 16);
    camera.lookAt(0, 0, 0);
    scene.add(new THREE.AmbientLight(0x8899ff, 0.7));
    const key = new THREE.DirectionalLight(0x00e5ff, 1.1);
    key.position.set(6, 10, 8); scene.add(key);
    const rim = new THREE.DirectionalLight(0xff2d78, 0.5);
    rim.position.set(-8, -4, -6); scene.add(rim);
    // starfield
    const sg = new THREE.BufferGeometry();
    const sp = new Float32Array(600 * 3);
    for (let i = 0; i < 600; i++) {
      sp[i * 3] = (Math.random() - .5) * 90;
      sp[i * 3 + 1] = (Math.random() - .5) * 50;
      sp[i * 3 + 2] = (Math.random() - .5) * 90;
    }
    sg.setAttribute("position", new THREE.BufferAttribute(sp, 3));
    scene.add(new THREE.Points(sg, new THREE.PointsMaterial({ color: 0x3a5a8a, size: 0.12 })));
  }
  if (hopGroup) scene.remove(hopGroup);
  pulseNodes = [];
  hopGroup = new THREE.Group();

  const n = Math.max(hops.length, 1);
  const spread = Math.min(6.5, (n - 1) * 3.2);
  const pts = [];
  hops.forEach((h, i) => {
    const x = n === 1 ? 0 : -spread / 2 + (spread * i) / (n - 1);
    const y = Math.sin(i * 1.3) * 1.1;
    const bad = h.anomalies.length > 0;
    const col = bad ? 0xff2d78 : 0x00e5ff;
    const node = new THREE.Mesh(
      new THREE.SphereGeometry(0.85, 32, 32),
      new THREE.MeshStandardMaterial({ color: col, emissive: col, emissiveIntensity: 0.55,
                                       roughness: 0.25, metalness: 0.6 }));
    node.position.set(x, y, 0);
    hopGroup.add(node);
    if (bad) pulseNodes.push(node);
    // glow shell
    const shell = new THREE.Mesh(
      new THREE.SphereGeometry(1.15, 24, 24),
      new THREE.MeshBasicMaterial({ color: col, transparent: true, opacity: 0.14 }));
    shell.position.copy(node.position);
    hopGroup.add(shell);
    if (bad) pulseNodes.push(shell);
    const label = labelSprite(`${i + 1}. ${h.by_host || h.from_host || "?"}`, bad ? "#ff6b9d" : "#7df3ff");
    label.position.set(x, y + 2.0, 0);
    hopGroup.add(label);
    pts.push(new THREE.Vector3(x, y, 0));
  });

  if (pts.length > 1) {
    const curve = new THREE.CatmullRomCurve3(pts);
    const tube = new THREE.Mesh(
      new THREE.TubeGeometry(curve, 64, 0.07, 8, false),
      new THREE.MeshBasicMaterial({ color: 0x00e5ff, transparent: true, opacity: 0.5 }));
    hopGroup.add(tube);
    // flowing dash packets along the path
    for (let k = 0; k < 14; k++) {
      const pkt = new THREE.Mesh(new THREE.SphereGeometry(0.14, 12, 12),
        new THREE.MeshBasicMaterial({ color: 0xbffcff }));
      pkt.userData = { curve, t: k / 14 };
      hopGroup.add(pkt);
      (hopGroup.userData.packets = hopGroup.userData.packets || []).push(pkt);
    }
  }
  scene.add(hopGroup);

  const w = canvas.clientWidth || 800, hgt = 380;
  renderer.setSize(w, hgt, false);
  camera.aspect = w / hgt; camera.updateProjectionMatrix();

  if (!raf) {
    let mouseX = 0;
    addEventListener("mousemove", e => { mouseX = (e.clientX / innerWidth - 0.5); });
    const clock = new THREE.Clock();
    (function animate() {
      raf = requestAnimationFrame(animate);
      const t = clock.getElapsedTime();
      hopGroup.rotation.y = Math.sin(t * 0.18) * 0.35 + mouseX * 0.5;
      hopGroup.position.y = Math.sin(t * 0.7) * 0.15;
      pulseNodes.forEach((p, i) => {
        const s = 1 + 0.28 * Math.sin(t * 4 + i);
        p.scale.set(s, s, s);
      });
      (hopGroup.userData.packets || []).forEach(pkt => {
        pkt.userData.t = (pkt.userData.t + 0.0035) % 1;
        pkt.position.copy(pkt.userData.curve.getPoint(pkt.userData.t));
      });
      renderer.render(scene, camera);
    })();
  }
}
