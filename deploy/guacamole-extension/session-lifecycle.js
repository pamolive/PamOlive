(() => {
  const tokenKey = "GUAC_AUTH_TOKEN";
  if (!window.localStorage.getItem(tokenKey)) return;

  let closeRequested = false;
  const requestClose = () => {
    if (closeRequested) return;
    closeRequested = true;
    window.setTimeout(() => window.close(), 500);
  };

  const originalRemoveItem = Storage.prototype.removeItem;
  Storage.prototype.removeItem = function removePamOliveSessionItem(key) {
    originalRemoveItem.call(this, key);
    if (this === window.localStorage && key === tokenKey) requestClose();
  };

  const tokenMonitor = window.setInterval(() => {
    if (!window.localStorage.getItem(tokenKey)) {
      window.clearInterval(tokenMonitor);
      requestClose();
    }
  }, 750);
})();
