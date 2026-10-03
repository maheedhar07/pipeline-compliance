// Dashboard behaviour. No inline scripts anywhere (CSP: script-src 'self'); page data arrives in
// <script type="application/json" id="page-data"> blocks (never executed) and behaviour via data-* attributes.
(function () {
  "use strict";
  const root = document.documentElement;
  const charts = [];
  const css = (n) => getComputedStyle(root).getPropertyValue(n).trim();
  const colors = () => ({ ok: css("--c-ok"), warn: css("--c-warn"), bad: css("--c-bad"), info: css("--c-info"), grid: css("--grid"), ink: css("--ink") });

  function pchChart(id, build) {
    const el = document.getElementById(id);
    if (!el || typeof Chart === "undefined") return;
    const make = () => {
      const c = colors();
      Chart.defaults.color = c.ink;
      Chart.defaults.borderColor = c.grid;
      return new Chart(el, build(c));
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
  document.addEventListener("htmx:afterSwap", (ev) => applyBarWidths(ev.target));

  // ---- per-page charts
  const pages = {
    overview(D, SCAN) {
      const go = (u) => { window.location = u + (SCAN ? (u.includes("?") ? "&" : "?") + "scan=" + encodeURIComponent(SCAN) : ""); };
      pchChart("donut", (c) => ({
        type: "doughnut",
        data: { labels: ["Compliant", "At risk", "Non-compliant"], datasets: [{ data: [D.status_counts.COMPLIANT, D.status_counts.AT_RISK, D.status_counts.NON_COMPLIANT], backgroundColor: [c.ok, c.warn, c.bad], borderWidth: 0 }] },
        options: { maintainAspectRatio: false, cutout: "62%", plugins: { legend: { display: false } },
          onClick: (e, els) => { if (els.length) go("/repos?status=" + ["COMPLIANT", "AT_RISK", "NON_COMPLIANT"][els[0].index]); } },
      }));
      pchChart("trend", (c) => ({
        type: "line",
        data: { labels: D.trend.map((t) => t.date), datasets: [
          { label: "Compliant %", data: D.trend.map((t) => t.compliant_pct), borderColor: c.ok, backgroundColor: c.ok, tension: 0.25, pointRadius: 4 },
          { label: "Non-compliant %", data: D.trend.map((t) => t.non_compliant_pct), borderColor: c.bad, backgroundColor: c.bad, tension: 0.25, pointRadius: 4 },
          { label: "Avg score", data: D.trend.map((t) => t.avg_score), borderColor: c.info, backgroundColor: c.info, borderDash: [4, 3], tension: 0.25, pointRadius: 3 }] },
        options: { maintainAspectRatio: false, scales: { y: { min: 0, max: 100, grid: { color: c.grid } }, x: { grid: { display: false } } }, plugins: { legend: { position: "bottom", labels: { boxWidth: 10 } } },
          onClick: (e, els) => { if (els.length) go("/scans?selected=" + encodeURIComponent(D.trend[els[0].index].scan_id)); } },
      }));
      pchChart("toprules", (c) => ({
        type: "bar",
        data: { labels: D.top_rules.map((r) => r.id), datasets: [{ label: "Failing repos", data: D.top_rules.map((r) => r.fail), backgroundColor: c.bad, borderRadius: 2 }] },
        options: { indexAxis: "y", maintainAspectRatio: false, plugins: { legend: { display: false }, tooltip: { callbacks: { afterLabel: (i) => D.top_rules[i.dataIndex].title } } },
          scales: { x: { grid: { color: c.grid } }, y: { grid: { display: false } } },
          onClick: (e, els) => { if (els.length) go("/rules/" + encodeURIComponent(D.top_rules[els[0].index].id)); } },
      }));
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
    const page = document.body.dataset.page;
    const p = pageData();
    if (page && pages[page] && p.data) pages[page](p.data, p.scan || "");
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init); else init();
})();
