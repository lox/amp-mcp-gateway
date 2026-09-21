let activeTab = null;

async function load() {
  [activeTab] = await chrome.tabs.query({active: true, currentWindow: true});
  document.querySelector("#tab").textContent = activeTab?.title || activeTab?.url || "No active tab";
  const stored = await chrome.storage.session.get("bridgeConfig");
  if (stored.bridgeConfig?.gatewayURL) document.querySelector("#gateway").value = stored.bridgeConfig.gatewayURL;
  await refreshStatus();
}

async function refreshStatus() {
  const state = await chrome.runtime.sendMessage({type: "status"});
  const status = document.querySelector("#status");
  status.textContent = state.message;
  status.className = `status ${state.connected ? "connected" : state.configured ? "" : "error"}`;
  document.querySelector("#pair").hidden = state.connected;
  document.querySelector("#disconnect").hidden = !state.configured;
}

document.querySelector("#pair").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = event.target.querySelector("button");
  button.disabled = true;
  const gatewayURL = document.querySelector("#gateway").value.trim();
  try {
    const result = await chrome.runtime.sendMessage({
      type: "pair",
      gatewayURL,
      pairingCode: document.querySelector("#code").value,
      tabId: activeTab.id,
    });
    if (!result.ok) throw new Error(result.error);
    await new Promise((resolve) => setTimeout(resolve, 300));
    await refreshStatus();
  } catch (error) {
    const status = document.querySelector("#status");
    status.textContent = error.message;
    status.className = "status error";
  } finally {
    button.disabled = false;
  }
});

document.querySelector("#disconnect").addEventListener("click", async () => {
  await chrome.runtime.sendMessage({type: "disconnect"});
  await refreshStatus();
});

load();
