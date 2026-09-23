let socket = null;
let heartbeat = null;
let reconnectTimer = null;
let currentConfig = null;
const completedCommands = new Set();

chrome.runtime.onInstalled.addListener(() => reconnectStored());
chrome.runtime.onStartup.addListener(() => reconnectStored());
chrome.tabs.onRemoved.addListener((tabId) => {
  if (currentConfig?.tabId === tabId) disconnect("The shared tab was closed.");
});
chrome.debugger.onDetach.addListener((source) => {
  if (currentConfig?.tabId === source.tabId) disconnect("Chrome detached the debugger.", false);
});

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type === "status") {
    status().then(sendResponse);
    return true;
  }
  if (message.type === "pair") {
    pair(message).then(() => sendResponse({ok: true})).catch((error) => sendResponse({ok: false, error: error.message}));
    return true;
  }
  if (message.type === "disconnect") {
    disconnect("Disconnected.").then(() => sendResponse({ok: true}));
    return true;
  }
});

async function reconnectStored() {
  const stored = await chrome.storage.session.get("bridgeConfig");
  if (!stored.bridgeConfig) return;
  currentConfig = stored.bridgeConfig;
  try {
    await chrome.tabs.get(currentConfig.tabId);
    await attach(currentConfig.tabId);
    connect();
  } catch (error) {
    await setStatus("disconnected", error.message);
  }
}

async function pair(message) {
  const gatewayURL = normalizeGatewayURL(message.gatewayURL);
  const tab = await chrome.tabs.get(message.tabId);
  if (!/^https?:/.test(tab.url || "")) throw new Error("Chrome can only share HTTP(S) tabs.");
  if (!message.pairingCode) throw new Error("Enter the pairing code from the gateway.");
  if (currentConfig?.tabId && currentConfig.tabId !== tab.id) {
    await detach(currentConfig.tabId);
  }
  await attach(tab.id);
  const stored = await chrome.storage.local.get("installID");
  const installID = stored.installID || crypto.randomUUID();
  await chrome.storage.local.set({installID});
  currentConfig = {
    gatewayURL,
    pairingCode: message.pairingCode.trim(),
    installID,
    shareID: crypto.randomUUID(),
    tabId: tab.id,
  };
  await chrome.storage.session.set({bridgeConfig: currentConfig});
  await setStatus("connecting", `Connecting ${tab.title || tab.url}`);
  connect();
}

function normalizeGatewayURL(raw) {
  const url = new URL(raw);
  if (url.username || url.password || url.search || url.hash || (url.pathname !== "/" && url.pathname !== "")) {
    throw new Error("Use only the gateway origin, without a path, credentials, query, or fragment.");
  }
  if (url.protocol !== "https:" && !(url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname))) {
    throw new Error("The gateway must use HTTPS, except on loopback.");
  }
  return url.origin;
}

async function attach(tabId) {
  try {
    await chrome.debugger.attach({tabId}, "1.3");
  } catch (error) {
    if (!error.message.includes("Another debugger is already attached")) throw error;
  }
  const target = {tabId};
  await chrome.debugger.sendCommand(target, "Page.enable");
  await chrome.debugger.sendCommand(target, "DOM.enable");
  await chrome.debugger.sendCommand(target, "Accessibility.enable");
}

async function detach(tabId) {
  try {
    await chrome.debugger.detach({tabId});
  } catch (_) {
    // Already detached.
  }
}

function connect() {
  clearTimeout(reconnectTimer);
  if (socket) {
    socket.onclose = null;
    socket.close();
  }
  const url = new URL(currentConfig.gatewayURL);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  url.pathname = "/browser/connect";
  socket = new WebSocket(url.toString());
  socket.onopen = async () => {
    const tab = await chrome.tabs.get(currentConfig.tabId);
    send({
      type: "hello",
      pairing_code: currentConfig.pairingCode,
      install_id: currentConfig.installID,
      share_id: currentConfig.shareID,
      tab_id: currentConfig.tabId,
      tab_title: tab.title || "",
      tab_url: tab.url || "",
    });
    clearInterval(heartbeat);
    heartbeat = setInterval(() => send({type: "ping"}), 20000);
  };
  socket.onmessage = (event) => receive(JSON.parse(event.data));
  socket.onerror = () => {};
  socket.onclose = async (event) => {
    clearInterval(heartbeat);
    heartbeat = null;
    if (!currentConfig) return;
    const rejected = event.code === 1008;
    await setStatus(rejected ? "disconnected" : "offline", rejected ? "Pairing was rejected or revoked." : "Gateway connection lost; reconnecting.");
    if (!rejected) reconnectTimer = setTimeout(connect, 3000);
  };
}

async function receive(message) {
  if (message.type === "paired") {
    const tab = await chrome.tabs.get(currentConfig.tabId);
    await setStatus("connected", `Sharing ${tab.title || tab.url}`);
    return;
  }
  if (message.type !== "command" || !message.id) return;
  if (completedCommands.has(message.id)) {
    send({type: "result", id: message.id, error: "Duplicate command rejected without executing."});
    return;
  }
  completedCommands.add(message.id);
  if (completedCommands.size > 1000) completedCommands.delete(completedCommands.values().next().value);
  try {
    const result = await execute(message.tool, message.arguments || {});
    send({type: "result", id: message.id, result});
  } catch (error) {
    send({type: "result", id: message.id, error: String(error.message || error).slice(0, 1000)});
  }
}

async function execute(tool, args) {
  switch (tool) {
    case "snapshot":
      return snapshot();
    case "screenshot":
      return screenshot();
    case "click":
      return click(args.backend_node_id);
    case "type":
      return typeText(args.backend_node_id, args.text, args.submit === true);
    case "scroll":
      return scroll(args.delta_y);
    case "navigate":
      return navigate(args.url);
    default:
      throw new Error(`Unknown browser command: ${tool}`);
  }
}

async function snapshot() {
  const tab = await chrome.tabs.get(currentConfig.tabId);
  const tree = await command("Accessibility.getFullAXTree", {depth: 20});
  const nodes = tree.nodes.map((node) => {
    const properties = {};
    for (const property of node.properties || []) {
      if (["checked", "disabled", "expanded", "focused", "required", "selected"].includes(property.name)) {
        properties[property.name] = property.value?.value;
      }
    }
    return {
      node_id: node.nodeId,
      parent_node_id: node.parentId,
      backend_node_id: node.backendDOMNodeId,
      role: node.role?.value,
      name: node.name?.value,
      value: node.value?.value,
      description: node.description?.value,
      ...properties,
    };
  }).filter((node) => node.backend_node_id && (node.role || node.name || node.value)).slice(0, 500);
  return {title: tab.title || "", url: tab.url || "", nodes, truncated: tree.nodes.length > 500};
}

async function screenshot() {
  const tab = await chrome.tabs.get(currentConfig.tabId);
  const result = await command("Page.captureScreenshot", {format: "png", captureBeyondViewport: false});
  return {title: tab.title || "", url: tab.url || "", mime_type: "image/png", screenshot_data: result.data};
}

async function click(backendNodeId) {
  await command("DOM.scrollIntoViewIfNeeded", {backendNodeId});
  const {model} = await command("DOM.getBoxModel", {backendNodeId});
  const quad = model.content || model.border;
  const x = (quad[0] + quad[2] + quad[4] + quad[6]) / 4;
  const y = (quad[1] + quad[3] + quad[5] + quad[7]) / 4;
  await command("Input.dispatchMouseEvent", {type: "mouseMoved", x, y});
  await command("Input.dispatchMouseEvent", {type: "mousePressed", x, y, button: "left", clickCount: 1});
  await command("Input.dispatchMouseEvent", {type: "mouseReleased", x, y, button: "left", clickCount: 1});
  return {clicked: backendNodeId};
}

async function typeText(backendNodeId, text, submit) {
  await command("DOM.scrollIntoViewIfNeeded", {backendNodeId});
  await command("DOM.focus", {backendNodeId});
  const {os} = await chrome.runtime.getPlatformInfo();
  const modifiers = selectAllModifier(os);
  await command("Input.dispatchKeyEvent", {type: "keyDown", key: "a", code: "KeyA", modifiers});
  await command("Input.dispatchKeyEvent", {type: "keyUp", key: "a", code: "KeyA", modifiers});
  await command("Input.dispatchKeyEvent", {type: "keyDown", key: "Backspace", code: "Backspace"});
  await command("Input.dispatchKeyEvent", {type: "keyUp", key: "Backspace", code: "Backspace"});
  await command("Input.insertText", {text});
  if (submit) {
    await command("Input.dispatchKeyEvent", {type: "keyDown", key: "Enter", code: "Enter"});
    await command("Input.dispatchKeyEvent", {type: "keyUp", key: "Enter", code: "Enter"});
  }
  return {typed: backendNodeId, submitted: submit};
}

function selectAllModifier(platform) {
  return platform === "mac" ? 4 : 2;
}

async function scroll(deltaY) {
  await command("Input.dispatchMouseEvent", {type: "mouseWheel", x: 0, y: 0, deltaX: 0, deltaY});
  return {scrolled: deltaY};
}

async function navigate(raw) {
  const url = new URL(raw);
  if (url.protocol !== "https:" && url.protocol !== "http:") throw new Error("Navigation requires an HTTP(S) URL.");
  const result = await command("Page.navigate", {url: url.toString()});
  if (result.errorText) throw new Error(result.errorText);
  return {url: url.toString(), frame_id: result.frameId};
}

function command(method, params = {}) {
  if (!currentConfig) return Promise.reject(new Error("No tab is shared."));
  return chrome.debugger.sendCommand({tabId: currentConfig.tabId}, method, params);
}

function send(message) {
  if (socket?.readyState === WebSocket.OPEN) socket.send(JSON.stringify(message));
}

async function disconnect(message, detachDebugger = true) {
  clearTimeout(reconnectTimer);
  clearInterval(heartbeat);
  if (socket) {
    socket.onclose = null;
    socket.close();
    socket = null;
  }
  const tabId = currentConfig?.tabId;
  currentConfig = null;
	await chrome.storage.session.remove("bridgeConfig");
  if (detachDebugger && tabId) await detach(tabId);
  await setStatus("disconnected", message);
}

async function status() {
  const stored = await chrome.storage.session.get(["bridgeStatus", "bridgeMessage", "bridgeConfig"]);
  return {
    status: stored.bridgeStatus || "disconnected",
    message: stored.bridgeMessage || "No tab is shared.",
    connected: stored.bridgeStatus === "connected",
    configured: Boolean(stored.bridgeConfig),
  };
}

async function setStatus(value, message) {
  await chrome.storage.session.set({bridgeStatus: value, bridgeMessage: message});
  await chrome.action.setBadgeText({text: value === "connected" ? "ON" : ""});
  await chrome.action.setBadgeBackgroundColor({color: "#216442"});
}

reconnectStored();
