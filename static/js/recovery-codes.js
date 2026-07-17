(() => {
  const button = document.getElementById("recovery-codes-download");
  if (!button) return;

  button.addEventListener("click", () => {
    const codes = Array.from(document.querySelectorAll("[data-recovery-code]"), (element) =>
      element.textContent.trim(),
    );
    if (!codes.length) return;
    const content = [
      "PAM-olive recovery codes",
      "Store this file offline. Each code can be used only once.",
      "",
      ...codes,
      "",
    ].join("\n");
    const url = URL.createObjectURL(new Blob([content], { type: "text/plain;charset=utf-8" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = button.dataset.filename || "pam-olive-recovery-codes.txt";
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  });
})();
