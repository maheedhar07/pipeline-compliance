// Dashboard behaviour. No inline scripts anywhere (CSP: script-src 'self'); page data arrives in
// <script type="application/json" id="page-data"> blocks (never executed) and behaviour via data-* attributes.
(function () {
  "use strict";
  const root = document.documentElement;
  const charts = [];
  const css = (n) => getComputedStyle(root).getPropertyValue(n).trim();
  const colors = () => ({ ok: css("--c-ok"), warn: css("--c-warn"), bad: css("--c-bad"), info: css("--c-info"), grid: css("--grid"), ink: css("--ink"),
    crit: css("--c-crit"), high: css("--c-high"), med: css("--c-med"), low: css("--c-low") });

  // Chart click targets arrive as data-urls="[[url,...],...]" (indexed [dataset][point]), built server side with the selected scan.
  // Only same-site absolute paths are followed.
  function urlAt(el, dataset, index) {
    try {
      const urls = JSON.parse(el.dataset.urls || "[]");
      const u = (urls[dataset] || [])[index];
      return typeof u === "string" && u.charAt(0) === "/" && u.charAt(1) !== "/" && u.charAt(1) !== "\\" ? u : null;
    } catch (e) { return null; }
  }
  function linkify(el, cfg) {
    if (!el.dataset.urls) return cfg;
    const o = cfg.options = cfg.options || {};
    o.onClick = (e, els) => { if (els.length) { const u = urlAt(el, els[0].datasetIndex, els[0].index); if (u) window.location = u; } };
    o.onHover = (e, els) => { if (e.native && e.native.target) e.native.target.style.cursor = els.length ? "pointer" : "default"; };
    return cfg;
  }

  function pchChart(id, build) {
    const el = document.getElementById(id);
    if (!el || typeof Chart === "undefined") return;
    const make = () => {
      const c = colors();
      Chart.defaults.color = c.ink;
      Chart.defaults.borderColor = c.grid;
      return new Chart(el, linkify(el, build(c)));
    };
    charts.push({ build: make, chart: make() });
  }
  function refreshCharts() { charts.forEach((e) => { e.chart.destroy(); e.chart = e.build(); }); }

  function pageData() {
    const el = document.getElementById("page-data");
    if (!el) return {};
    try { return JSON.parse(el.textContent || "{}"); } catch (e) { return {}; }
  }

  // ---- generic behaviours (event delegation, so HTMX-swapped content keeps working)
  document.addEventListener("click", (ev) => {
    const t = ev.target.closest("[data-action='toggle-theme']");
    if (t) {
      root.classList.toggle("dark");
      try { localStorage.setItem("pch-theme", root.classList.contains("dark") ? "dark" : "light"); } catch (e) { /* ignore */ }
      refreshCharts();
      return;
    }
    const h = ev.target.closest("[data-href]");
    if (h && !ev.target.closest("a")) window.location = h.dataset.href;
  });
  document.addEventListener("change", (ev) => {
    const el = ev.target;
    if (el.matches && el.matches("[data-autosubmit]") && el.form) el.form.submit();
    if (el.id === "show-pass") {
      document.querySelectorAll("li.passing").forEach((li) => li.classList.toggle("hidden", !el.checked));
    }
  });

  function applyBarWidths(scope) {
    (scope || document).querySelectorAll("[data-w]").forEach((el) => {
      const v = Number(el.dataset.w);
      if (isFinite(v)) el.style.width = Math.max(0, Math.min(100, v)) + "%"; // CSSOM, allowed by style-src 'self'
    });
  }
  function applyHeights(scope) {
    (scope || document).querySelectorAll("[data-h]").forEach((el) => {
      const v = Number(el.dataset.h);
      if (isFinite(v) && v > 0) el.style.height = Math.min(900, v) + "px";
    });
  }

  // ---- column chooser: hidden columns per table are kept per viewer in localStorage (all wrapped: the table works without it)
  const colKey = (id) => "pch-cols-v2-" + id;
  function hiddenCols(chooser) {
    const id = chooser.dataset.colChooser;
    try {
      const raw = localStorage.getItem(colKey(id));
      if (raw !== null) { const v = JSON.parse(raw); if (Array.isArray(v)) return v.map(String); }
    } catch (e) { /* storage blocked or corrupt: use the defaults */ }
    return (chooser.dataset.defaultOff || "").split(",").filter(Boolean);
  }
  function applyColumns(scope) {
    document.querySelectorAll("[data-col-chooser]").forEach((chooser) => {
      const hidden = hiddenCols(chooser);
      chooser.querySelectorAll("[data-col-toggle]").forEach((cb) => { cb.checked = !hidden.includes(cb.dataset.colToggle); });
      const table = document.querySelector("[data-table='" + chooser.dataset.colChooser + "']");
      if (!table || (scope && !table.contains(scope) && !scope.contains(table) && scope !== document)) return;
      table.querySelectorAll("[data-col]").forEach((cell) => cell.classList.toggle("hidden", hidden.includes(cell.dataset.col)));
    });
  }
  function saveColumns(chooser, hidden) {
    try { localStorage.setItem(colKey(chooser.dataset.colChooser), JSON.stringify(hidden)); } catch (e) { /* ignore */ }
  }
  document.addEventListener("change", (ev) => {
    const cb = ev.target.closest && ev.target.closest("[data-col-toggle]");
    if (!cb) return;
    const chooser = cb.closest("[data-col-chooser]");
    saveColumns(chooser, Array.from(chooser.querySelectorAll("[data-col-toggle]")).filter((x) => !x.checked).map((x) => x.dataset.colToggle));
    applyColumns(document);
  });
  document.addEventListener("click", (ev) => {
    const reset = ev.target.closest("[data-col-reset]");
    if (reset) { const chooser = reset.closest("[data-col-chooser]"); saveColumns(chooser, []); applyColumns(document); return; }
    const flow = ev.target.closest("[data-flow-toggle]");
    if (flow) {
      const row = document.getElementById(flow.dataset.flowToggle);
      if (!row) return;
      const open = row.classList.toggle("hidden") === false;
      flow.setAttribute("aria-expanded", open ? "true" : "false");
    }
  });
  document.addEventListener("htmx:afterSwap", (ev) => { applyBarWidths(ev.target); applyHeights(ev.target); });
  document.addEventListener("htmx:afterSettle", () => applyColumns(document));

  // ---- per-page charts
  const pages = {
    overview(D) {
      const short = (s) => { const v = String(s).split("@")[0]; return v.length > 26 ? v.slice(0, 25) + "…" : v; };
      const stackedBars = (bd) => (c) => ({
        type: "bar",
        data: { labels: bd.items.map((i) => short(i.name)), datasets: [
          { label: "Compliant", data: bd.items.map((i) => i.compliant), backgroundColor: c.ok },
          { label: "At risk", data: bd.items.map((i) => i.at_risk), backgroundColor: c.warn },
          { label: "Non-compliant", data: bd.items.map((i) => i.non_compliant), backgroundColor: c.bad }] },
        options: { indexAxis: "y", maintainAspectRatio: false, interaction: { mode: "nearest", intersect: true },
          plugins: { legend: { position: "bottom", labels: { boxWidth: 10 } }, tooltip: { callbacks: { title: (items) => (items.length ? bd.items[items[0].dataIndex].name : "") } } },
          scales: { x: { stacked: true, grid: { color: c.grid }, ticks: { precision: 0 } }, y: { stacked: true, grid: { display: false } } } },
      });
      pchChart("donut", (c) => ({
        type: "doughnut",
        data: { labels: ["Compliant", "At risk", "Non-compliant"], datasets: [{ data: [D.status_counts.COMPLIANT, D.status_counts.AT_RISK, D.status_counts.NON_COMPLIANT], backgroundColor: [c.ok, c.warn, c.bad], borderWidth: 0 }] },
        options: { maintainAspectRatio: false, cutout: "62%", plugins: { legend: { display: false } } },
      }));
      pchChart("severity", (c) => ({
        type: "bar",
        data: { labels: ["Critical", "High", "Medium", "Low"], datasets: [{ label: "Failing findings", data: ["critical", "high", "medium", "low"].map((k) => D.severity_counts[k]), backgroundColor: [c.crit, c.high, c.med, c.low], borderRadius: 2 }] },
        options: { maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { y: { grid: { color: c.grid }, ticks: { precision: 0 } }, x: { grid: { display: false } } } },
      }));
      pchChart("migration", (c) => ({
        type: "doughnut",
        data: { labels: D.migration_states.map((m) => m.label), datasets: [{ data: D.migration_states.map((m) => m.repos), backgroundColor: [c.warn, c.info, c.ok], borderWidth: 0 }] },
        options: { maintainAspectRatio: false, cutout: "58%", plugins: { legend: { display: false } } },
      }));
      pchChart("byproject", stackedBars(D.by_project));
      pchChart("byowner", stackedBars(D.by_owner));
      pchChart("trend", (c) => ({
        type: "line",
        data: { labels: D.trend.map((t) => t.date), datasets: [
          { label: "Compliant %", data: D.trend.map((t) => t.compliant_pct), borderColor: c.ok, backgroundColor: c.ok, tension: 0.25, pointRadius: 4 },
          { label: "Non-compliant %", data: D.trend.map((t) => t.non_compliant_pct), borderColor: c.bad, backgroundColor: c.bad, tension: 0.25, pointRadius: 4 },
          { label: "Avg score", data: D.trend.map((t) => t.avg_score), borderColor: c.info, backgroundColor: c.info, borderDash: [4, 3], tension: 0.25, pointRadius: 3 }] },
        options: { maintainAspectRatio: false, scales: { y: { min: 0, max: 100, grid: { color: c.grid } }, x: { grid: { display: false } } }, plugins: { legend: { position: "bottom", labels: { boxWidth: 10 } } } },
      }));
      pchChart("toprules", (c) => ({
        type: "bar",
        data: { labels: D.top_rules.map((r) => r.id), datasets: [{ label: "Failing repos", data: D.top_rules.map((r) => r.fail), backgroundColor: c.bad, borderRadius: 2 }] },
        options: { indexAxis: "y", maintainAspectRatio: false, plugins: { legend: { display: false }, tooltip: { callbacks: { afterLabel: (i) => D.top_rules[i.dataIndex].title } } },
          scales: { x: { grid: { color: c.grid } }, y: { grid: { display: false } } } },
      }));
    },
    repos(D, SCAN) {
      // score of this repo across scans; the point colour is its status, a click opens that scan's page for the repo
      const T = D.trend;
      pchChart("repo-trend", (c) => {
        const col = { COMPLIANT: c.ok, AT_RISK: c.warn, NON_COMPLIANT: c.bad };
        return {
          type: "line",
          data: { labels: T.map((t) => t.date), datasets: [{ label: "Score", data: T.map((t) => t.score), borderColor: c.info, backgroundColor: c.info, tension: 0.25, pointRadius: 5,
            pointBackgroundColor: T.map((t) => col[t.status] || c.info) }] },
          options: { maintainAspectRatio: false, scales: { y: { min: 0, max: 100, grid: { color: c.grid } }, x: { grid: { display: false } } }, plugins: { legend: { display: false },
            tooltip: { callbacks: { afterLabel: (i) => T[i.dataIndex].status.replace("_", " ").toLowerCase() } } } },
        };
      });
    },
    targets(D, SCAN) {
      pchChart("tg", (c) => ({
        type: "bar",
        data: { labels: D.targets.map((t) => t.label), datasets: [
          { label: "Repos", data: D.targets.map((t) => t.repos), backgroundColor: c.info, borderRadius: 2 },
          { label: "Non-compliant", data: D.targets.map((t) => t.non_compliant), backgroundColor: c.bad, borderRadius: 2 }] },
        options: { maintainAspectRatio: false, plugins: { legend: { position: "bottom", labels: { boxWidth: 10 } } }, scales: { y: { grid: { color: c.grid }, ticks: { precision: 0 } }, x: { grid: { display: false } } },
          onClick: (e, els) => { if (els.length) window.location = "/repos?target=" + encodeURIComponent(D.targets[els[0].index].target) + (SCAN ? "&scan=" + encodeURIComponent(SCAN) : ""); } },
      }));
    },
    testing(D) {
      pchChart("cov", (c) => ({
        type: "bar",
        data: { labels: Object.keys(D.coverage_buckets).map((k) => k + "%"), datasets: [{ label: "Repos", data: Object.values(D.coverage_buckets), backgroundColor: Object.keys(D.coverage_buckets).map((k, i) => (i >= 8 ? c.ok : (i >= 6 ? c.warn : c.bad))), borderRadius: 2 }] },
        options: { maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { y: { grid: { color: c.grid }, ticks: { precision: 0 } }, x: { grid: { display: false } } } },
      }));
    },
    migration(D) {
      pchChart("plat", (c) => ({
        type: "doughnut",
        data: { labels: Object.keys(D.platforms), datasets: [{ data: Object.values(D.platforms), backgroundColor: [c.warn, c.bad, c.ok, c.info], borderWidth: 0 }] },
        options: { maintainAspectRatio: false, cutout: "55%", plugins: { legend: { position: "bottom", labels: { boxWidth: 10 } } } },
      }));
      pchChart("ready", (c) => ({
        type: "bar",
        data: { labels: Object.keys(D.buckets), datasets: [{ label: "Repos", data: Object.values(D.buckets), backgroundColor: [c.bad, c.warn, c.info, c.ok], borderRadius: 2 }] },
        options: { maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { y: { grid: { color: c.grid }, ticks: { precision: 0 } }, x: { grid: { display: false } } } },
      }));
    },
  };

  function init() {
    applyBarWidths(document);
    applyHeights(document);
    applyColumns(document);
    const page = document.body.dataset.page;
    const p = pageData();
    if (page && pages[page] && p.data) pages[page](p.data, p.scan || "");
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init); else init();
})();
