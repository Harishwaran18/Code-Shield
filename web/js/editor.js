import { api, wsUrl } from "./api.js";
import { navigate, state } from "./app.js";
import { avatar, clear, el, emptyState, toast } from "./dom.js";

const LANGUAGES = ["python", "javascript", "typescript", "java", "go", "other"];
const STARTER = `# Code-Shield collaborative room
# Share this room with your team and scan before you ship.

def greet(name):
    return f"Hello, {name}!"
`;

export async function renderEditor() {
  let rooms = [];
  try {
    rooms = await api("/api/rooms");
  } catch (error) {
    if (error.status === 401) {
      navigate("/login");
      return el("div");
    }
    toast(error.message, "error");
  }

  let current = null;
  let socket = null;
  let disposed = false;
  let reconnectAttempts = 0;
  let reconnectTimer = null;
  let saveTimer = null;
  let editTimer = null;
  let lastSavedCode = "";

  const roomList = el("div", { class: "room-list" });
  const roomTitle = el("h2", {}, "Select a room");
  const presence = el("div", { class: "presence" });
  const scanMeta = el("span", { class: "muted" }, "idle");
  const status = el("span", { class: "muted" }, "offline");
  const cursorInfo = el("span", { class: "muted" }, "Ln 1, Col 1");
  const results = el("div", { class: "findings" }, emptyState("Run a scan to see findings."));
  const chatLog = el("div", { class: "chat-log" }, emptyState("No messages yet."));

  const codeArea = el("textarea", {
    class: "code-area", spellcheck: "false", "aria-label": "Code editor",
    placeholder: "# Start typing your code…",
  });
  const gutter = el("div", { class: "gutter", "aria-hidden": "true" }, "1");

  const languageSelect = el("select", { class: "input", "aria-label": "Language" },
    LANGUAGES.map((language) => el("option", { value: language }, language)));
  languageSelect.value = "python";

  const scanButton = el("button", { class: "btn btn-primary btn-sm", type: "button" }, "Scan code");
  const saveButton = el("button", { class: "btn btn-sm", type: "button" }, "Save");
  const createName = el("input", { class: "input", placeholder: "Room name", maxlength: "80" });
  const joinId = el("input", { class: "input", placeholder: "Room ID", maxlength: "40" });

  function setStatus(text) {
    status.textContent = text;
  }

  function renderRooms() {
    clear(roomList);
    if (!rooms.length) {
      roomList.append(emptyState("No rooms yet — create one below."));
      return;
    }
    for (const room of rooms) {
      roomList.append(el("button", {
        class: `room-item${current?.id === room.id ? " active" : ""}`,
        type: "button",
        onclick: () => selectRoom(room.id),
      },
        el("span", { class: "room-name" }, room.name),
        el("span", { class: "room-meta" }, `${room.language} · ${room.members} member${room.members === 1 ? "" : "s"}`)));
    }
  }

  function renderPresence(members) {
    clear(presence);
    for (const member of members) {
      presence.append(avatar(member.name));
    }
    presence.setAttribute("aria-label", `${members.length} collaborator(s) online`);
  }

  function updateGutter() {
    const lines = codeArea.value.split("\n").length;
    clear(gutter);
    for (let index = 1; index <= lines; index += 1) gutter.append(el("div", {}, String(index)));
    gutter.scrollTop = codeArea.scrollTop;
  }

  function updateCursor() {
    const upto = codeArea.value.slice(0, codeArea.selectionStart);
    const lines = upto.split("\n");
    cursorInfo.textContent = `Ln ${lines.length}, Col ${lines[lines.length - 1].length + 1}`;
  }

  function applyRemoteCode(code) {
    if (code === codeArea.value) return;
    const start = codeArea.selectionStart;
    const end = codeArea.selectionEnd;
    codeArea.value = code;
    codeArea.setSelectionRange(Math.min(start, code.length), Math.min(end, code.length));
    updateGutter();
  }

  function send(message) {
    if (socket && socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify(message));
  }

  function scheduleSave() {
    clearTimeout(saveTimer);
    saveTimer = setTimeout(saveNow, 2200);
  }

  async function saveNow() {
    if (!current || codeArea.value === lastSavedCode) return;
    try {
      const updated = await api(`/api/rooms/${current.id}/code`, {
        method: "PUT",
        body: { code: codeArea.value, language: languageSelect.value },
      });
      current = updated;
      lastSavedCode = codeArea.value;
      setStatus("saved");
    } catch (error) {
      setStatus("save failed");
      if (error.status === 401) navigate("/login");
    }
  }

  async function selectRoom(roomId) {
    if (current?.id === roomId) return;
    await saveNow();
    disconnect();
    try {
      current = await api(`/api/rooms/${roomId}`);
    } catch (error) {
      toast(error.message, "error");
      return;
    }
    roomTitle.textContent = current.name;
    languageSelect.value = current.language;
    codeArea.value = current.code || STARTER;
    lastSavedCode = codeArea.value;
    clear(results);
    results.append(emptyState("Run a scan to see findings."));
    scanMeta.textContent = "idle";
    clear(chatLog);
    chatLog.append(emptyState("No messages yet."));
    updateGutter();
    updateCursor();
    renderRooms();
    connect();
  }

  async function createRoom() {
    const name = createName.value.trim();
    if (name.length < 2) {
      toast("Room name must be at least 2 characters", "error");
      return;
    }
    try {
      const room = await api("/api/rooms", { method: "POST", body: { name, language: languageSelect.value } });
      rooms = [room, ...rooms];
      createName.value = "";
      renderRooms();
      await selectRoom(room.id);
      toast("Room created", "success");
    } catch (error) {
      toast(error.message, "error");
    }
  }

  async function joinRoom() {
    const roomId = joinId.value.trim();
    if (!roomId) return;
    try {
      const room = await api(`/api/rooms/${roomId}/join`, { method: "POST" });
      if (!rooms.some((item) => item.id === room.id)) rooms = [room, ...rooms];
      joinId.value = "";
      renderRooms();
      await selectRoom(room.id);
      toast("Joined room", "success");
    } catch (error) {
      toast(error.message, "error");
    }
  }

  function connect() {
    disconnect();
    if (!current || disposed) return;
    const ws = new WebSocket(wsUrl(`/ws/rooms/${current.id}`));
    socket = ws;
    setStatus("connecting…");
    ws.onopen = () => {
      if (socket !== ws) return;
      reconnectAttempts = 0;
      setStatus("live");
    };
    ws.onmessage = (event) => {
      try {
        handleMessage(JSON.parse(event.data));
      } catch {
        /* ignore malformed frames */
      }
    };
    ws.onclose = () => {
      if (socket !== ws || disposed) return;
      setStatus("reconnecting…");
      scheduleReconnect();
    };
  }

  function scheduleReconnect() {
    if (disposed || reconnectAttempts >= 5) {
      setStatus("offline");
      return;
    }
    reconnectAttempts += 1;
    clearTimeout(reconnectTimer);
    reconnectTimer = setTimeout(connect, Math.min(1000 * 2 ** reconnectAttempts, 15000));
  }

  function disconnect() {
    clearTimeout(reconnectTimer);
    reconnectTimer = null;
    if (socket) {
      const ws = socket;
      socket = null;
      ws.onclose = null;
      try {
        ws.close();
      } catch {
        /* already closed */
      }
    }
  }

  function handleMessage(message) {
    if (message.type === "snapshot") {
      if (typeof message.room?.code === "string") {
        codeArea.value = message.room.code;
        lastSavedCode = message.room.code;
        updateGutter();
      }
      if (message.room?.language) languageSelect.value = message.room.language;
    } else if (message.type === "presence") {
      renderPresence(message.members || []);
    } else if (message.type === "edit" && message.user?.id !== state.user?.id) {
      applyRemoteCode(message.code || "");
      lastSavedCode = message.code || "";
    } else if (message.type === "chat") {
      appendChat(message.user?.name || "Someone", message.message || "");
    }
  }

  function appendChat(who, text) {
    if (chatLog.querySelector(".empty")) clear(chatLog);
    chatLog.append(el("div", { class: "chat-msg" }, el("span", { class: "who" }, who), text));
    chatLog.scrollTop = chatLog.scrollHeight;
  }

  async function runScan() {
    if (!current) {
      toast("Create or select a room first", "error");
      return;
    }
    scanButton.disabled = true;
    scanMeta.textContent = "scanning…";
    clear(results);
    results.append(emptyState("Analysing code…"));
    try {
      const scan = await api("/api/scans", {
        method: "POST",
        body: { code: codeArea.value, language: languageSelect.value, room_id: current.id },
      });
      renderScan(scan);
    } catch (error) {
      clear(results);
      results.append(emptyState(error.message));
      scanMeta.textContent = "failed";
      if (error.status === 401) navigate("/login");
    } finally {
      scanButton.disabled = false;
    }
  }

  function renderScan(scan) {
    clear(results);
    scanMeta.textContent = `${scan.findings_count} findings · risk ${scan.risk_score}/100`;
    if (!scan.findings.length) {
      results.append(emptyState("No issues found. Nice work!"));
      return;
    }
    for (const finding of scan.findings) {
      results.append(el("article", { class: "finding" },
        el("div", { class: "finding-head" },
          el("span", { class: `badge sev-${finding.severity}` }, finding.severity),
          el("span", { class: "finding-title" }, finding.title)),
        el("p", { class: "finding-desc" }, finding.description),
        el("div", { class: "finding-meta" },
          el("span", {}, `line ${finding.line}`),
          finding.cwe ? el("span", {}, finding.cwe) : null,
          el("span", {}, finding.source)),
        finding.remediation ? el("p", { class: "remediation" }, finding.remediation) : null));
    }
  }

  codeArea.addEventListener("input", () => {
    updateGutter();
    updateCursor();
    scheduleSave();
    clearTimeout(editTimer);
    editTimer = setTimeout(() => send({ type: "edit", code: codeArea.value }), 70);
  });
  codeArea.addEventListener("scroll", () => {
    gutter.scrollTop = codeArea.scrollTop;
  });
  codeArea.addEventListener("click", updateCursor);
  codeArea.addEventListener("keyup", updateCursor);
  codeArea.addEventListener("keydown", (event) => {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "s") {
      event.preventDefault();
      saveNow();
      return;
    }
    if (event.key === "Tab") {
      event.preventDefault();
      const start = codeArea.selectionStart;
      codeArea.setRangeText("    ", start, codeArea.selectionEnd, "end");
      updateGutter();
      scheduleSave();
    }
  });

  languageSelect.addEventListener("change", async () => {
    if (!current) return;
    try {
      current = await api(`/api/rooms/${current.id}/code`, {
        method: "PUT",
        body: { code: codeArea.value, language: languageSelect.value },
      });
      lastSavedCode = codeArea.value;
      toast(`Language set to ${languageSelect.value}`, "success");
    } catch (error) {
      toast(error.message, "error");
    }
  });

  const chatInput = el("input", { class: "input", placeholder: "Message your team…", maxlength: "2000" });
  const chatForm = el("form", { class: "chat-form" },
    chatInput,
    el("button", { class: "btn btn-sm btn-primary", type: "submit" }, "Send"));
  chatForm.addEventListener("submit", (event) => {
    event.preventDefault();
    const text = chatInput.value.trim();
    if (!text) return;
    send({ type: "chat", message: text });
    chatInput.value = "";
  });

  scanButton.addEventListener("click", runScan);
  saveButton.addEventListener("click", saveNow);

  const sidebar = el("aside", { class: "sidebar" },
    el("div", { class: "card card-pad" },
      el("div", { class: "panel-title" }, "Rooms", el("span", { class: "muted" }, String(rooms.length))),
      roomList,
      el("div", { class: "stack" },
        el("div", { class: "field" }, createName,
          el("button", { class: "btn btn-sm btn-block", type: "button", onclick: createRoom }, "Create room")),
        el("div", { class: "field" }, joinId,
          el("button", { class: "btn btn-sm btn-block", type: "button", onclick: joinRoom }, "Join by ID")))),
    el("div", { class: "card card-pad" },
      el("div", { class: "panel-title" }, "Your session"),
      el("div", { class: "row" },
        avatar(state.user.name),
        el("div", {},
          el("div", { class: "table-user" }, state.user.name),
          el("div", { class: "table-sub" }, state.user.email))),
      el("p", { class: "small muted" }, `Role: ${state.user.role}`),
      el("p", { class: "small muted" }, "Sessions are scored continuously by the anomaly detector.")));

  const main = el("section", { class: "editor-main" },
    el("div", { class: "card card-pad" },
      el("div", { class: "editor-toolbar" },
        roomTitle,
        el("span", { class: "spacer" }),
        presence,
        languageSelect,
        saveButton,
        scanButton),
      el("div", { class: "editor-shell" }, gutter, codeArea),
      el("div", { class: "editor-status" },
        status,
        cursorInfo,
        el("span", { class: "muted" }, "Ctrl/Cmd+S to save"))));

  const side = el("aside", { class: "editor-side stack" },
    el("div", { class: "card card-pad" },
      el("div", { class: "panel-title" }, "Security scan", scanMeta),
      results),
    el("div", { class: "card card-pad" },
      el("div", { class: "panel-title" }, "Team chat"),
      chatLog,
      chatForm));

  const layout = el("div", { class: "editor-layout" }, sidebar, main, side);

  async function cleanup() {
    disposed = true;
    clearTimeout(saveTimer);
    clearTimeout(editTimer);
    clearTimeout(reconnectTimer);
    await saveNow();
    disconnect();
  }
  layout.__cleanup = cleanup;

  renderRooms();
  if (rooms.length) {
    await selectRoom(rooms[0].id);
  } else {
    roomTitle.textContent = "Create your first room";
    setStatus("offline");
  }
  return layout;
}
