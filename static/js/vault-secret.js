(() => {
  const masked = "••••••••••••";

  function closeSecret(button) {
    const output = button.closest(".secret-output");
    if (output) output.innerHTML = `<span>${masked}</span>`;
  }

  function startTotp(root) {
    const url = root.dataset.totpUrl;
    if (!url || root.dataset.totpRunning === "true") return;
    root.dataset.totpRunning = "true";
    let remaining = 30;
    let period = 30;

    const paint = () => {
      const label = root.querySelector("[data-totp-remaining]");
      const bar = root.querySelector("[data-totp-progress]");
      if (label) label.textContent = `${remaining} s`;
      if (bar) bar.style.width = `${Math.max(0, (remaining / period) * 100)}%`;
    };
    const refresh = async () => {
      try {
        const response = await fetch(url, {credentials: "same-origin", cache: "no-store"});
        if (!response.ok) throw new Error("TOTP refresh denied");
        const data = await response.json();
        const code = root.querySelector("[data-totp-code]");
        if (code) code.textContent = data.code;
        remaining = data.remaining;
        period = data.period;
        paint();
      } catch (_error) {
        root.dataset.totpRunning = "false";
      }
    };
    refresh();
    const timer = window.setInterval(() => {
      if (!root.isConnected) return window.clearInterval(timer);
      remaining -= 1;
      if (remaining <= 0) refresh();
      paint();
    }, 1000);
  }

  document.addEventListener("click", (event) => {
    const button = event.target.closest("[data-secret-close]");
    if (button) closeSecret(button);
  });
  document.body.addEventListener("htmx:afterSwap", (event) => {
    event.detail.target.querySelectorAll("[data-totp-url]").forEach(startTotp);
  });
})();
