(() => {
  const root = document.documentElement;
  const csrf = document.querySelector('meta[name="csrf-token"]')?.content || "";

  const applyTheme = (preference) => {
    root.dataset.themePreference = preference;
    root.dataset.theme = preference === "system"
      ? (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark")
      : preference;
  };

  const save = async (data) => {
    const body = new URLSearchParams(data);
    const response = await fetch("/account/preferences/ui/", {
      method: "POST",
      credentials: "same-origin",
      headers: {"X-CSRFToken": csrf, "Content-Type": "application/x-www-form-urlencoded"},
      body,
    });
    if (!response.ok) throw new Error("Preference update failed");
    return response.json();
  };

  document.querySelector("[data-theme-toggle]")?.addEventListener("click", async () => {
    const next = root.dataset.theme === "light" ? "dark" : "light";
    applyTheme(next);
    try { await save({preferred_theme: next}); } catch (_error) { /* keep local choice */ }
  });

  document.querySelector("[data-language-select]")?.addEventListener("change", async (event) => {
    try {
      await save({preferred_language: event.target.value});
      window.location.reload();
    } catch (_error) {
      event.target.value = root.lang;
    }
  });

  matchMedia("(prefers-color-scheme: light)").addEventListener("change", () => {
    if (root.dataset.themePreference === "system") applyTheme("system");
  });
})();
