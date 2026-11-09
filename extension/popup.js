const st = document.getElementById("status"), on = document.getElementById("on");
chrome.storage.sync.get({ enabled: true }, (v) => (on.checked = v.enabled));
on.addEventListener("change", () => chrome.storage.sync.set({ enabled: on.checked }));

chrome.runtime.sendMessage({ type: "health" }, (r) => {
  if (chrome.runtime.lastError || !r || !r.ok) {
    st.className = "bad";
    st.innerHTML = "Server not running.<br>Start it with <code>python server.py</code>";
    return;
  }
  st.className = "ok";
  st.textContent = "Connected · AI " + (r.data.llm ? "on" : "off (rules only)");
});
