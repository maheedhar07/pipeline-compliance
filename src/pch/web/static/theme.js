// Apply the stored theme before first paint (loaded synchronously in <head>; no inline script, CSP-safe).
(function () {
  try {
    var t = localStorage.getItem("pch-theme");
    var d = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
    if (t === "dark" || (!t && d)) document.documentElement.classList.add("dark");
  } catch (e) { /* storage blocked: fall back to the default theme */ }
})();
