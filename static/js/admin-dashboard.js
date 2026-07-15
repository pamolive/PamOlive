(() => {
  const dashboard = document.querySelector("[data-admin-dashboard-url]");
  if (!dashboard) return;

  const setMetric = (name, value) => {
    dashboard.querySelectorAll(`[data-admin-metric="${name}"]`).forEach((node) => {
      node.textContent = value;
    });
  };
  const setService = (name, status) => {
    const node = dashboard.querySelector(`[data-service="${name}"]`);
    if (!node) return;
    node.classList.toggle("is-ok", status === "ok");
    node.classList.toggle("is-error", status !== "ok");
    const label = node.querySelector("small");
    if (label) label.textContent = status === "ok"
      ? dashboard.dataset.operationalLabel
      : dashboard.dataset.errorLabel;
  };
  const renderFailures = (failures) => {
    const list = dashboard.querySelector("[data-failure-list]");
    if (!list) return;
    list.replaceChildren();
    if (!failures.length) {
      const empty = document.createElement("div");
      empty.className = "empty-state compact-empty";
      empty.textContent = dashboard.dataset.emptyFailureLabel;
      list.append(empty);
      return;
    }
    failures.forEach((failure) => {
      const row = document.createElement("div");
      row.className = "failure-log-row";
      const icon = document.createElement("span");
      icon.textContent = "!";
      const copy = document.createElement("div");
      const title = document.createElement("strong");
      title.textContent = failure.username;
      const detail = document.createElement("small");
      detail.textContent = `${failure.source_ip} · ${new Date(failure.at).toLocaleString()}`;
      copy.append(title, detail);
      row.append(icon, copy);
      list.append(row);
    });
  };
  const refresh = async () => {
    try {
      const response = await fetch(dashboard.dataset.adminDashboardUrl, {
        credentials: "same-origin",
        cache: "no-store",
      });
      if (!response.ok) throw new Error("Dashboard refresh denied");
      const data = await response.json();
      ["connected_users", "active_sessions", "failed_logins", "pending_approvals", "audit_events_24h"].forEach((key) => setMetric(key, data[key]));
      setService("database", data.database);
      setService("cache", data.cache);
      renderFailures(data.failures);
      const refreshed = dashboard.querySelector("[data-last-refresh]");
      if (refreshed) refreshed.textContent = new Date().toLocaleTimeString();
    } catch (_error) {
      setService("database", "error");
      setService("cache", "error");
    }
  };
  window.setInterval(refresh, 15000);
})();
