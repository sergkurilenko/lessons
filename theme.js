// Переключатель темы. Начальная тема уже выставлена инлайн-скриптом в <head>
// (чтобы не мигало при загрузке); здесь только синхронизируем кнопку и клик.
(function () {
  const root = document.documentElement;
  const btn = document.getElementById("theme-toggle");

  function apply(theme) {
    root.dataset.theme = theme;
    if (!btn) return;
    const dark = theme === "dark";
    btn.querySelector(".theme-icon").textContent = dark ? "☀" : "☾";
    btn.setAttribute("aria-label", dark ? "Светлая тема" : "Тёмная тема");
    btn.setAttribute("aria-pressed", String(dark));
  }

  apply(root.dataset.theme === "dark" ? "dark" : "light");

  if (btn) {
    btn.addEventListener("click", () => {
      const next = root.dataset.theme === "dark" ? "light" : "dark";
      try {
        localStorage.setItem("rakurs-theme", next);
      } catch (e) {}
      apply(next);
    });
  }
})();
