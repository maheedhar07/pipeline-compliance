// Standalone Tailwind CLI config (v3.x). Build with scripts/build_css.sh.
module.exports = {
  darkMode: "class",
  content: ["./src/pch/web/templates/**/*.html", "./src/pch/web/static/*.js", "./src/pch/web/*.py"],
  theme: { extend: {} },
  plugins: [],
};
