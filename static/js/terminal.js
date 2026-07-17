(() => {
  const shell = document.getElementById("pam-terminal");
  const output = document.getElementById("terminal-output");
  if (!shell || !output || !window.Terminal) return;

  const sessionId = shell.dataset.sessionId;
  let ticket = shell.dataset.sessionTicket;
  delete shell.dataset.sessionTicket;
  const status = document.getElementById("terminal-status");
  const statusDot = document.getElementById("terminal-status-dot");
  const command = document.getElementById("terminal-command");
  const commandSend = document.getElementById("terminal-command-send");
  const copySelectionButton = document.getElementById("terminal-copy-selection");
  const copyAllButton = document.getElementById("terminal-copy-all");
  const closeNotice = document.getElementById("terminal-close-notice");
  const closeTabButton = document.getElementById("terminal-close-tab");
  const emulator = new window.Terminal({
    cursorBlink: true,
    cursorStyle: "block",
    convertEol: false,
    fontFamily: "ui-monospace, SFMono-Regular, Consolas, monospace",
    fontSize: 13,
    lineHeight: 1.15,
    scrollback: 10000,
    theme: {
      background: "#050a07",
      foreground: "#d8e0d8",
      cursor: "#bddb62",
      cursorAccent: "#050a07",
      selectionBackground: "#526c1877",
      black: "#101713",
      red: "#ff8f86",
      green: "#bddb62",
      yellow: "#e7bd69",
      blue: "#87b7d6",
      magenta: "#c59ad9",
      cyan: "#7bc8b6",
      white: "#e8eee7",
      brightBlack: "#66736a",
      brightRed: "#ffb0aa",
      brightGreen: "#d2ef78",
      brightYellow: "#f1d292",
      brightBlue: "#add2e8",
      brightMagenta: "#ddb8eb",
      brightCyan: "#a2dfd1",
      brightWhite: "#ffffff",
    },
  });
  emulator.open(output);
  emulator.writeln("pam-olive · Vérification du ticket éphémère…");

  const websocketScheme = window.location.protocol === "https:" ? "wss" : "ws";
  const socket = new WebSocket(
    `${websocketScheme}://${window.location.host}/ws/sessions/${sessionId}/terminal/`,
  );
  let connected = false;
  let wasConnected = false;

  const writeClipboard = async (text) => {
    if (!text) return false;
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (_error) {
      const fallback = document.createElement("textarea");
      fallback.value = text;
      fallback.setAttribute("readonly", "");
      fallback.style.position = "fixed";
      fallback.style.opacity = "0";
      document.body.appendChild(fallback);
      fallback.select();
      const copied = document.execCommand("copy");
      fallback.remove();
      return copied;
    }
  };

  const showCopyFeedback = (label) => {
    const previous = status.textContent;
    status.textContent = label;
    window.setTimeout(() => {
      if (connected) status.textContent = previous;
    }, 1200);
  };

  const copySelection = async () => {
    if (!emulator.hasSelection()) return;
    if (await writeClipboard(emulator.getSelection())) {
      showCopyFeedback("Sélection copiée");
    }
  };

  const terminalBufferText = () => {
    const buffer = emulator.buffer.active;
    let outputText = "";
    for (let index = 0; index < buffer.length; index += 1) {
      const line = buffer.getLine(index);
      if (!line) continue;
      if (outputText && !line.isWrapped) outputText += "\n";
      outputText += line.translateToString(true);
    }
    return outputText.trimEnd();
  };

  const copyAll = async () => {
    if (await writeClipboard(terminalBufferText())) {
      showCopyFeedback("Sortie du terminal copiée");
    }
  };

  const attemptToCloseTab = () => {
    window.close();
    window.setTimeout(() => {
      if (closeNotice) {
        closeNotice.querySelector("span").textContent =
          "La fermeture automatique a été bloquée par le navigateur.";
      }
    }, 700);
  };

  const sendInput = (data) => {
    if (!connected || socket.readyState !== WebSocket.OPEN || !data) return;
    socket.send(JSON.stringify({ type: "terminal.input", data: data.slice(0, 65536) }));
  };

  const fitTerminal = () => {
    const bounds = output.getBoundingClientRect();
    const cols = Math.min(400, Math.max(20, Math.floor((bounds.width - 32) / 7.9)));
    const rows = Math.min(200, Math.max(5, Math.floor((bounds.height - 32) / 15.2)));
    if (emulator.cols !== cols || emulator.rows !== rows) emulator.resize(cols, rows);
    if (connected && socket.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify({ type: "terminal.resize", cols, rows }));
    }
  };

  emulator.attachCustomKeyEventHandler((event) => {
    if (event.type !== "keydown") return true;
    const copyShortcut =
      (event.ctrlKey || event.metaKey) &&
      event.key.toLowerCase() === "c" &&
      (event.shiftKey || emulator.hasSelection());
    if (!copyShortcut) return true;
    copySelection();
    return false;
  });
  emulator.onData(sendInput);
  emulator.onSelectionChange(() => {
    copySelectionButton.disabled = !emulator.hasSelection();
  });
  copySelectionButton.addEventListener("click", copySelection);
  copyAllButton.addEventListener("click", copyAll);
  closeTabButton.addEventListener("click", attemptToCloseTab);
  commandSend.addEventListener("click", () => {
    const pasted = command.value.slice(0, 65535);
    if (!pasted.trim()) return;
    const normalized = pasted.replace(/\r?\n/g, "\r");
    sendInput(normalized.endsWith("\r") ? normalized : `${normalized}\r`);
    command.value = "";
    emulator.focus();
  });

  socket.addEventListener("message", (event) => {
    const message = JSON.parse(event.data);
    if (message.state === "authorization_required") {
      socket.send(JSON.stringify({ type: "authorize", ticket }));
      ticket = null;
      return;
    }
    if (message.state === "authorized") {
      status.textContent = "Autorisation validée";
      emulator.writeln("pam-olive · Ticket consommé, vérification de la cible SSH…");
      return;
    }
    if (message.state === "connected") {
      connected = true;
      wasConnected = true;
      status.textContent = "Session SSH active";
      statusDot.classList.add("is-connected");
      commandSend.disabled = false;
      emulator.clear();
      fitTerminal();
      emulator.focus();
      return;
    }
    if (message.type === "terminal.output") {
      const binary = Uint8Array.from(window.atob(message.data), (character) =>
        character.charCodeAt(0),
      );
      emulator.write(binary);
      return;
    }
    if (message.state === "gateway_not_configured") {
      status.textContent = "Broker indisponible";
      statusDot.classList.add("is-error");
      emulator.writeln("\r\npam-olive · Le broker isolé n’est pas configuré.");
      return;
    }
    if (message.type === "error") {
      status.textContent = "Accès refusé";
      statusDot.classList.add("is-error");
      emulator.writeln(`\r\npam-olive · ${message.message}`);
    }
  });

  socket.addEventListener("close", (event) => {
    connected = false;
    commandSend.disabled = true;
    if (!statusDot.classList.contains("is-error")) status.textContent = "Session terminée";
    statusDot.classList.remove("is-connected");
    if (wasConnected && event.code === 1000) {
      closeNotice.hidden = false;
      window.setTimeout(attemptToCloseTab, 1600);
    }
  });

  socket.addEventListener("error", () => {
    status.textContent = "Connexion impossible";
    statusDot.classList.add("is-error");
    emulator.writeln("\r\npam-olive · Le canal sécurisé n’a pas pu être établi.");
  });

  new ResizeObserver(fitTerminal).observe(output);
})();
