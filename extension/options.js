async function load() {
  const stored = await chrome.storage.local.get("gatewayURL");
  if (stored.gatewayURL) document.querySelector("#gateway").value = stored.gatewayURL;
}

document.querySelector("#settings").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = event.target.querySelector("button");
  const status = document.querySelector("#status");
  button.disabled = true;
  status.textContent = "";
  status.className = "status";
  try {
    const result = await chrome.runtime.sendMessage({type: "configureGateway", gatewayURL: document.querySelector("#gateway").value.trim()});
    if (!result.ok) throw new Error(result.error);
    document.querySelector("#gateway").value = result.gatewayURL;
    status.textContent = "Gateway saved. You can close this tab and pair from the extension.";
  } catch (error) {
    status.textContent = error.message;
    status.className = "status error";
  } finally {
    button.disabled = false;
  }
});

load();
