(() => {
  const root = document.documentElement;
  const allowedThemes = new Set(["system", "light", "dark"]);
  const serverPreference = root.dataset.themePreference || "system";
  const storedPreference = localStorage.getItem("pamolive.theme");
  const preference = allowedThemes.has(storedPreference)
    ? storedPreference
    : serverPreference;
  const systemTheme = matchMedia("(prefers-color-scheme: light)").matches
    ? "light"
    : "dark";
  root.dataset.themePreference = preference;
  root.dataset.theme = preference === "system" ? systemTheme : preference;
})();
