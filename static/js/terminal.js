(() => {
  const terminal = document.getElementById("pam-terminal");
  if (!terminal) return;

  const sessionId = terminal.dataset.sessionId;
  let ticket = terminal.dataset.sessionTicket;
  delete terminal.dataset.sessionTicket;
  const status = document.getElementById("terminal-status");
  const statusDot = document.getElementById("terminal-status-dot");
  const output = document.getElementById("terminal-output");
  const decoder = new TextDecoder("utf-8");
  const websocketScheme = window.location.protocol === "https:" ? "wss" : "ws";
  const socket = new WebSocket(
    `${websocketScheme}://${window.location.host}/ws/sessions/${sessionId}/terminal/`,
  );
  let connected = false;

  const line = (message) => {
    output.textContent += `${message}\n`;
    output.scrollTop = output.scrollHeight;
  };

  const sendResize = () => {
    if (!connected || socket.readyState !== WebSocket.OPEN) return;
    const cols = Math.max(20, Math.floor(output.clientWidth / 7.2));
    const rows = Math.max(5, Math.floor(output.clientHeight / 16));
    socket.send(JSON.stringify({ type: "terminal.resize", cols, rows }));
  };

  socket.addEventListener("message", (event) => {
    const message = JSON.parse(event.data);
    if (message.state === "authorization_required") {
      socket.send(JSON.stringify({ type: "authorize", ticket }));
      ticket = null;
      return;
    }
    if (message.state === "authorized") {
      status.textContent = "Autorisation validée";
      line("pam-olive · Ticket consommé, vérification de la cible SSH…");
      return;
    }
    if (message.state === "connected") {
      connected = true;
      status.textContent = "Session SSH active";
      statusDot.classList.add("is-connected");
      output.textContent = "";
      terminal.focus();
      sendResize();
      return;
    }
    if (message.type === "terminal.output") {
      const binary = Uint8Array.from(window.atob(message.data), (char) => char.charCodeAt(0));
      output.textContent += decoder.decode(binary, { stream: true });
      output.scrollTop = output.scrollHeight;
      return;
    }
    if (message.state === "gateway_not_configured") {
      status.textContent = "Broker indisponible";
      statusDot.classList.add("is-error");
      line("pam-olive · Le broker isolé n’est pas configuré.");
      return;
    }
    if (message.type === "error") {
      status.textContent = "Accès refusé";
      statusDot.classList.add("is-error");
      line(`pam-olive · ${message.message}`);
    }
  });

  const keySequence = (event) => {
    const named = {
      Enter: "\r",
      Backspace: "\x7f",
      Tab: "\t",
      Escape: "\x1b",
      ArrowUp: "\x1b[A",
      ArrowDown: "\x1b[B",
      ArrowRight: "\x1b[C",
      ArrowLeft: "\x1b[D",
      Home: "\x1b[H",
      End: "\x1b[F",
      Delete: "\x1b[3~",
    };
    if (named[event.key]) return named[event.key];
    if (event.ctrlKey && event.key.length === 1) {
      const code = event.key.toUpperCase().charCodeAt(0);
      if (code >= 64 && code <= 95) return String.fromCharCode(code - 64);
    }
    return !event.ctrlKey && !event.altKey && !event.metaKey && event.key.length === 1
      ? event.key
      : null;
  };

  terminal.addEventListener("keydown", (event) => {
    if (!connected || socket.readyState !== WebSocket.OPEN) return;
    const data = keySequence(event);
    if (data === null) return;
    event.preventDefault();
    socket.send(JSON.stringify({ type: "terminal.input", data }));
  });

  terminal.addEventListener("paste", (event) => {
    if (!connected || socket.readyState !== WebSocket.OPEN) return;
    event.preventDefault();
    const data = event.clipboardData.getData("text").slice(0, 65536);
    socket.send(JSON.stringify({ type: "terminal.input", data }));
  });

  socket.addEventListener("close", () => {
    connected = false;
    if (!statusDot.classList.contains("is-error")) {
      status.textContent = "Session terminée";
    }
    statusDot.classList.remove("is-connected");
  });

  socket.addEventListener("error", () => {
    status.textContent = "Connexion impossible";
    statusDot.classList.add("is-error");
    line("pam-olive · Le canal sécurisé n’a pas pu être établi.");
  });

  new ResizeObserver(sendResize).observe(output);
})();
