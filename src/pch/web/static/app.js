// Theme + Chart.js helpers (no build step).
(function () {
  const root = document.documentElement;
  const stored = (() => { try { return localStorage.getItem("pch-theme"); } catch (e) { return null; } })();
  const prefersDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
  if (stored === "dark" || (!stored && prefersDark)) root.classList.add("dark");
  window.pchToggleTheme = function () {
    root.classList.toggle("dark");
    try { localStorage.setItem("pch-theme", root.classList.contains("dark") ? "dark" : "light"); } catch (e) {}
    window.pchRefreshCharts();
  };
  const charts = [];
  const css = (n) => getComputedStyle(root).getPropertyValue(n).trim();
  window.pchColors = () => ({ ok: css("--c-ok"), warn: css("--c-warn"), bad: css("--c-bad"), info: css("--c-info"), grid: css("--grid"), ink: css("--ink") });
  window.pchChart = function (id, build) {
    const el = document.getElementById(id);
    if (!el || typeof Chart === "undefined") return;
    const make = () => {
      const c = window.pchColors();
      Chart.defaults.color = c.ink;
      Chart.defaults.borderColor = c.grid;
      const cfg = build(c);
      const ch = new Chart(el, cfg);
      return ch;
    };
    const entry = { el, build: make, chart: make() };
    charts.push(entry);
  };
  window.pchRefreshCharts = function () {
    charts.forEach((e) => { e.chart.destroy(); e.chart = e.build(); });
  };
  document.addEventListener("click", (ev) => {
    const t = ev.target.closest("[data-href]");
    if (t && !ev.target.closest("a")) window.location = t.dataset.href;
  });
})();
