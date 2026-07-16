(() => {
  const root = document.documentElement;
  const applyTheme = (preference) => {
    root.dataset.themePreference = preference;
    root.dataset.theme = preference === "system"
      ? (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark")
      : preference;
  };

  applyTheme(root.dataset.themePreference || "system");

  const themeSelect = document.querySelector("[data-theme-select]");
  if (themeSelect) themeSelect.value = root.dataset.themePreference || "system";

  themeSelect?.addEventListener("change", (event) => {
    const preference = event.target.value;
    localStorage.setItem("pamolive.theme", preference);
    applyTheme(preference);
    if (event.target.form?.matches("[data-preference-form]")) {
      event.target.form.requestSubmit();
    }
  });

  document.querySelector("[data-language-select]")?.addEventListener("change", (event) => {
    event.target.form.requestSubmit();
  });

  matchMedia("(prefers-color-scheme: light)").addEventListener("change", () => {
    if (root.dataset.themePreference === "system") applyTheme("system");
  });
})();
