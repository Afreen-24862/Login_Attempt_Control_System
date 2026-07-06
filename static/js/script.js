/* =========================================================
   LoginGuard — Global Front-End Behaviors
   ========================================================= */

document.addEventListener("DOMContentLoaded", function () {
  // ---- Initialize all Bootstrap toasts ----
  document.querySelectorAll(".toast").forEach((el) => {
    new bootstrap.Toast(el).show();
  });

  // ---- Dark / Light theme toggle ----
  const html = document.documentElement;
  const themeToggle = document.getElementById("themeToggle");
  const savedTheme = localStorage_safe_get("lacs-theme") || "dark";
  html.setAttribute("data-bs-theme", savedTheme);
  updateThemeIcon(savedTheme);

  if (themeToggle) {
    themeToggle.addEventListener("click", function () {
      const current = html.getAttribute("data-bs-theme");
      const next = current === "dark" ? "light" : "dark";
      html.setAttribute("data-bs-theme", next);
      localStorage_safe_set("lacs-theme", next);
      updateThemeIcon(next);
    });
  }

  function updateThemeIcon(theme) {
    if (!themeToggle) return;
    const icon = themeToggle.querySelector("i");
    icon.className = theme === "dark" ? "fa-solid fa-moon" : "fa-solid fa-sun";
  }

  // ---- Animated counters ----
  document.querySelectorAll(".stat-number[data-count]").forEach((el) => {
    const target = parseInt(el.getAttribute("data-count"), 10) || 0;
    animateCounter(el, target);
  });

  function animateCounter(el, target) {
    const duration = 1200;
    const start = performance.now();
    function step(now) {
      const progress = Math.min((now - start) / duration, 1);
      const value = Math.floor(progress * target);
      el.textContent = value.toLocaleString();
      if (progress < 1) requestAnimationFrame(step);
      else el.textContent = target.toLocaleString();
    }
    requestAnimationFrame(step);
  }

  // Safe localStorage wrappers (artifacts environments may block storage;
  // the main app runs on the user's own machine where this is fully supported)
  function localStorage_safe_get(key) {
    try { return localStorage.getItem(key); } catch (e) { return null; }
  }
  function localStorage_safe_set(key, value) {
    try { localStorage.setItem(key, value); } catch (e) { /* no-op */ }
  }
});
