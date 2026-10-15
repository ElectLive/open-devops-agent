/* Keep reading progress in sync with normal and instant page navigation. */
(() => {
  const progress = document.createElement("div");
  progress.className = "docs-reading-progress";
  progress.setAttribute("aria-hidden", "true");
  document.body.append(progress);
  let pending = false;

  function updateProgress() {
    const distance = document.documentElement.scrollHeight - window.innerHeight;
    const fraction = distance > 0 ? Math.min(1, Math.max(0, window.scrollY / distance)) : 0;
    progress.style.transform = `scaleX(${fraction})`;
    pending = false;
  }

  function scheduleUpdate() {
    if (!pending) {
      pending = true;
      window.requestAnimationFrame(updateProgress);
    }
  }

  window.addEventListener("scroll", scheduleUpdate, { passive: true });
  window.addEventListener("resize", scheduleUpdate, { passive: true });
  if (typeof document$ !== "undefined") {
    document$.subscribe(scheduleUpdate);
  }
  scheduleUpdate();
})();
