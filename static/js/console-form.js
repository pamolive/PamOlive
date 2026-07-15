(() => {
  const setVisible = (form, name, visible) => {
    const wrapper = form.querySelector(`[data-console-field="${name}"]`);
    if (!wrapper) return;
    wrapper.hidden = !visible;
    wrapper.querySelectorAll("input, select, textarea").forEach((control) => {
      control.disabled = !visible;
    });
  };

  document.querySelectorAll("[data-console-resource]").forEach((form) => {
    const resource = form.dataset.consoleResource;
    if (resource === "targets") {
      const protocol = form.querySelector('[name="protocol"]');
      const update = () => {
        const isRdp = protocol?.value === "rdp";
        ["rdp_security", "rdp_certificate_fingerprints", "rdp_server_layout", "rdp_resize_method"].forEach((name) => setVisible(form, name, isRdp));
        setVisible(form, "ssh_host_key_policy", !isRdp);
        setVisible(form, "credential_totp", !isRdp);
      };
      protocol?.addEventListener("change", update);
      update();
    }
    if (resource === "credentials") {
      const accountType = form.querySelector('[name="account_type"]');
      const kind = form.querySelector('[name="kind"]');
      const update = () => {
        setVisible(form, "domain", accountType?.value === "domain");
        setVisible(form, "totp_secret", kind?.value === "password");
      };
      accountType?.addEventListener("change", update);
      kind?.addEventListener("change", update);
      update();
    }
  });
})();
