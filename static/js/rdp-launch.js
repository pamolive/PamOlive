(() => {
  const form = document.getElementById("rdp-launch-form");
  if (!form) return;
  window.requestAnimationFrame(() => form.submit());
})();
