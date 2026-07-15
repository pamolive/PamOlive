(() => {
  const fieldsByType = {
    login: ["application", "website_url", "username", "password", "totp_secret", "notes"],
    totp: ["application", "website_url", "username", "totp_secret", "notes"],
    card: ["card_holder", "card_number", "expiry", "cvv", "notes"],
    note: ["notes"],
  };
  const alwaysVisible = new Set(["name", "item_type", "group", "favorite"]);

  document.querySelectorAll("[data-vault-form]").forEach((form) => {
    const typeSelect = form.querySelector('[name="item_type"]');
    if (!typeSelect) return;
    const update = () => {
      const visible = new Set(fieldsByType[typeSelect.value] || []);
      form.querySelectorAll("[data-vault-field]").forEach((wrapper) => {
        const name = wrapper.dataset.vaultField;
        const show = alwaysVisible.has(name) || visible.has(name);
        wrapper.hidden = !show;
        wrapper.querySelectorAll("input, select, textarea").forEach((control) => {
          control.disabled = !show;
        });
      });
    };
    typeSelect.addEventListener("change", update);
    update();
  });
})();
