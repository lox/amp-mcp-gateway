let socket = null;
let heartbeat = null;
let reconnectTimer = null;
let currentConfig = null;
let operationQueue = Promise.resolve();
const completedCommands = new Set();
const maxSnapshotBytes = 6 * 1024 * 1024;
const maxSnapshotTextLength = 16 * 1024;
const snapshotEncoder = new TextEncoder();

chrome.runtime.onInstalled.addListener(() => serialized(reconnectStored));
chrome.runtime.onStartup.addListener(() => serialized(reconnectStored));
chrome.tabs.onRemoved.addListener((tabId) => {
  disconnectIfCurrent(tabId, "The shared tab was closed.");
});
chrome.debugger.onDetach.addListener((source) => {
  disconnectIfCurrent(source.tabId, "Chrome detached the debugger.", false);
});

function disconnectIfCurrent(tabId, message, detachDebugger = true) {
  if (currentConfig?.tabId === tabId) serialized(() => {
    if (currentConfig?.tabId === tabId) return disconnect(message, detachDebugger);
  });
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type === "status") {
    status().then(sendResponse);
    return true;
  }
  if (message.type === "pair") {
    serialized(() => pair(message)).then(() => sendResponse({ok: true})).catch((error) => sendResponse({ok: false, error: error.message}));
    return true;
  }
  if (message.type === "disconnect") {
    serialized(() => disconnect("Disconnected.")).then(() => sendResponse({ok: true}));
    return true;
  }
});

function serialized(action) {
  const next = operationQueue.then(action, action);
  operationQueue = next.catch(() => {});
  return next;
}

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
  const config = currentConfig;
  if (!config) return;
  if (socket) {
    socket.onclose = null;
    socket.close();
  }
  const url = new URL(config.gatewayURL);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  url.pathname = "/browser/connect";
  const connectedSocket = new WebSocket(url.toString());
  socket = connectedSocket;
  connectedSocket.onopen = async () => {
    if (socket !== connectedSocket || currentConfig?.shareID !== config.shareID) return;
    const tab = await chrome.tabs.get(config.tabId);
    send({
      type: "hello",
      pairing_code: config.pairingCode,
      install_id: config.installID,
      share_id: config.shareID,
      tab_id: config.tabId,
      tab_title: tab.title || "",
      tab_url: tab.url || "",
    }, connectedSocket);
    clearInterval(heartbeat);
    heartbeat = setInterval(() => send({type: "ping"}, connectedSocket), 20000);
  };
  connectedSocket.onmessage = (event) => {
    if (socket === connectedSocket) receive(JSON.parse(event.data), config);
  };
  connectedSocket.onerror = () => {};
  connectedSocket.onclose = async (event) => {
    if (socket !== connectedSocket) return;
    socket = null;
    clearInterval(heartbeat);
    heartbeat = null;
    if (!currentConfig) return;
    const rejected = event.code === 1008;
    if (rejected) {
      await serialized(() => disconnect("Pairing was rejected or revoked."));
      return;
    }
    await setStatus("offline", "Gateway connection lost; reconnecting.");
    reconnectTimer = setTimeout(() => serialized(connect), 3000);
  };
}

async function receive(message, config) {
  if (message.type === "paired") {
    if (currentConfig?.shareID !== config.shareID) return;
    if (message.reconnect_code) {
      currentConfig.pairingCode = message.reconnect_code;
      await chrome.storage.session.set({bridgeConfig: currentConfig});
    }
    const tab = await chrome.tabs.get(config.tabId);
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
  const target = {tabId: config.tabId, shareID: config.shareID};
  await serialized(async () => {
    try {
      const result = await execute(target, message.tool, message.arguments || {});
      send({type: "result", id: message.id, result});
    } catch (error) {
      send({type: "result", id: message.id, error: String(error.message || error).slice(0, 1000)});
    }
  });
}

async function execute(target, tool, args) {
  switch (tool) {
    case "snapshot":
      return snapshot(target);
    case "screenshot":
      return screenshot(target);
    case "click":
      return click(target, args.document_id, args.backend_node_id, args.expected_url, args.expected_role, args.expected_name);
    case "type":
      return typeText(target, args.document_id, args.backend_node_id, args.expected_url, args.expected_role, args.expected_name, args.text, args.submit === true);
    case "scroll":
      return scroll(target, args.delta_y);
    case "navigate":
      return navigate(target, args.url);
    default:
      throw new Error(`Unknown browser command: ${tool}`);
  }
}

async function snapshot(target) {
  const tab = await chrome.tabs.get(target.tabId);
  const documentID = await currentDocument(target);
  const tree = await command(target, "Accessibility.getFullAXTree");
  if (await currentDocument(target) !== documentID) throw new Error("The document changed while it was being inspected.");
  const title = boundedSnapshotText(tab.title || "");
  const url = boundedSnapshotText(tab.url || "");
  const result = {title: title.value, url: url.value, document_id: documentID, nodes: [], truncated: title.truncated || url.truncated};
  let payloadBytes = snapshotEncoder.encode(JSON.stringify({...result, truncated: false})).byteLength;
  for (const node of tree.nodes) {
    if (!node.backendDOMNodeId || !(node.role?.value || node.name?.value || node.value?.value)) continue;
    const properties = {};
    for (const property of node.properties || []) {
      if (["checked", "disabled", "expanded", "focused", "required", "selected"].includes(property.name)) {
        properties[property.name] = property.value?.value;
      }
    }
    const role = boundedSnapshotText(node.role?.value);
    const name = boundedSnapshotText(node.name?.value);
    const value = boundedSnapshotText(node.value?.value);
    const description = boundedSnapshotText(node.description?.value);
    const snapshotNode = {
      node_id: node.nodeId,
      parent_node_id: node.parentId,
      backend_node_id: node.backendDOMNodeId,
      role: role.value,
      name: name.value,
      value: value.value,
      description: description.value,
      ...properties,
    };
    const nodeBytes = snapshotEncoder.encode(JSON.stringify(snapshotNode)).byteLength;
    if (payloadBytes + nodeBytes + (result.nodes.length ? 1 : 0) > maxSnapshotBytes) {
      result.truncated = true;
      break;
    }
    result.nodes.push(snapshotNode);
    payloadBytes += nodeBytes + (result.nodes.length > 1 ? 1 : 0);
    if (role.truncated || name.truncated || value.truncated || description.truncated) result.truncated = true;
  }
  return result;
}

function boundedSnapshotText(value) {
  if (typeof value !== "string" || value.length <= maxSnapshotTextLength) return {value, truncated: false};
  return {value: value.slice(0, maxSnapshotTextLength), truncated: true};
}

async function screenshot(target) {
  const tab = await chrome.tabs.get(target.tabId);
  const maxDataLength = 6 * 1024 * 1024;
  for (const quality of [70, 50, 30]) {
    const result = await command(target, "Page.captureScreenshot", {format: "jpeg", quality, captureBeyondViewport: false});
    if (result.data.length <= maxDataLength) {
      return {title: tab.title || "", url: tab.url || "", mime_type: "image/jpeg", screenshot_data: result.data};
    }
  }
  throw new Error("Screenshot exceeds the 6 MiB bridge payload limit.");
}

async function click(target, documentID, backendNodeId, expectedURL, expectedRole, expectedName) {
  await verifyNode(target, documentID, backendNodeId, expectedURL, expectedRole, expectedName);
  await documentCommand(target, documentID, "DOM.scrollIntoViewIfNeeded", {backendNodeId});
  await verifyNode(target, documentID, backendNodeId, expectedURL, expectedRole, expectedName);
  const {model} = await documentCommand(target, documentID, "DOM.getBoxModel", {backendNodeId});
  const quad = model.content || model.border;
  const x = (quad[0] + quad[2] + quad[4] + quad[6]) / 4;
  const y = (quad[1] + quad[3] + quad[5] + quad[7]) / 4;
  await documentCommand(target, documentID, "Input.dispatchMouseEvent", {type: "mouseMoved", x, y});
  await documentCommand(target, documentID, "Input.dispatchMouseEvent", {type: "mousePressed", x, y, button: "left", clickCount: 1});
  await documentCommand(target, documentID, "Input.dispatchMouseEvent", {type: "mouseReleased", x, y, button: "left", clickCount: 1});
  return {clicked: backendNodeId};
}

async function typeText(target, documentID, backendNodeId, expectedURL, expectedRole, expectedName, text, submit) {
  await verifyNode(target, documentID, backendNodeId, expectedURL, expectedRole, expectedName);
  await documentCommand(target, documentID, "DOM.scrollIntoViewIfNeeded", {backendNodeId});
  await verifyNode(target, documentID, backendNodeId, expectedURL, expectedRole, expectedName);
  await documentCommand(target, documentID, "DOM.focus", {backendNodeId});
  const {os} = await chrome.runtime.getPlatformInfo();
  const modifiers = selectAllModifier(os);
  await documentCommand(target, documentID, "Input.dispatchKeyEvent", {type: "keyDown", key: "a", code: "KeyA", modifiers});
  await documentCommand(target, documentID, "Input.dispatchKeyEvent", {type: "keyUp", key: "a", code: "KeyA", modifiers});
  await documentCommand(target, documentID, "Input.dispatchKeyEvent", {type: "keyDown", key: "Backspace", code: "Backspace"});
  await documentCommand(target, documentID, "Input.dispatchKeyEvent", {type: "keyUp", key: "Backspace", code: "Backspace"});
  await documentCommand(target, documentID, "Input.insertText", {text});
  if (submit) {
    await documentCommand(target, documentID, "Input.dispatchKeyEvent", {type: "keyDown", key: "Enter", code: "Enter"});
    await documentCommand(target, documentID, "Input.dispatchKeyEvent", {type: "keyUp", key: "Enter", code: "Enter"});
  }
  return {typed: backendNodeId, submitted: submit};
}

async function verifyNode(target, documentID, backendNodeId, expectedURL, expectedRole, expectedName) {
  if (typeof expectedURL !== "string" || typeof expectedRole !== "string" || typeof expectedName !== "string") {
    throw new Error("The mutation must identify the snapshotted URL, role, and accessible name.");
  }
  const tab = await chrome.tabs.get(target.tabId);
  if (tab.url !== expectedURL) throw new Error("The shared tab URL changed after the accessibility snapshot.");
  const tree = await documentCommand(target, documentID, "Accessibility.getPartialAXTree", {backendNodeId, fetchRelatives: false});
  const node = tree.nodes?.find((candidate) => candidate.backendDOMNodeId === backendNodeId);
  if (!node || node.role?.value !== expectedRole || node.name?.value !== expectedName) {
    throw new Error("The target element changed after the accessibility snapshot.");
  }
}

async function currentDocument(target) {
  const {frameTree} = await command(target, "Page.getFrameTree");
  return frameTree.frame.loaderId;
}

async function documentCommand(target, expectedDocument, method, params = {}) {
  if (!expectedDocument || await currentDocument(target) !== expectedDocument) {
    throw new Error("The document changed after the accessibility snapshot. Take a new snapshot before interacting.");
  }
  return command(target, method, params);
}

function selectAllModifier(platform) {
  return platform === "mac" ? 4 : 2;
}

async function scroll(target, deltaY) {
  if (typeof deltaY !== "number" || !Number.isFinite(deltaY) || Math.abs(deltaY) > 10000) {
    throw new Error("Scroll distance must be a finite number between -10000 and 10000.");
  }
  await command(target, "Runtime.evaluate", {expression: `window.scrollBy(0, ${deltaY})`});
  return {scrolled: deltaY};
}

async function navigate(target, raw) {
  const url = new URL(raw);
  if (url.protocol !== "https:" && url.protocol !== "http:") throw new Error("Navigation requires an HTTP(S) URL.");
  const result = await command(target, "Page.navigate", {url: url.toString()});
  if (result.errorText) throw new Error(result.errorText);
  return {url: url.toString(), frame_id: result.frameId};
}

function command(target, method, params = {}) {
  if (!target || currentConfig?.shareID !== target.shareID || currentConfig?.tabId !== target.tabId) {
    return Promise.reject(new Error("The shared tab changed before the command completed."));
  }
  return chrome.debugger.sendCommand({tabId: target.tabId}, method, params);
}

function send(message, destination = socket) {
  if (destination?.readyState === WebSocket.OPEN) destination.send(JSON.stringify(message));
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
