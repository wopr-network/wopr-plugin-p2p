/**
 * P2P Plugin UI Component for WOPR
 * 
 * Vanilla JS SolidJS component for managing P2P peers and invites.
 */

const { createSignal, onMount } = window.Solid || Solid;

export default function P2PPluginUI(props) {
  const [peers, setPeers] = createSignal([]);
  const [identity, setIdentity] = createSignal(null);
  const [newPeerKey, setNewPeerKey] = createSignal("");
  const [selectedSessions, setSelectedSessions] = createSignal("");
  const [inviteToken, setInviteToken] = createSignal("");
  const [pendingInvites, setPendingInvites] = createSignal([]);

  onMount(async () => {
    // Load identity and peers from API
    try {
      const idData = await props.api.getIdentity();
      setIdentity(idData);
      
      const peersData = await props.api.getPeers();
      setPeers(peersData.peers || []);
    } catch (err) {
      console.error("Failed to load P2P data:", err);
    }
  });

  const handleCreateInvite = async () => {
    if (!newPeerKey()) return;
    // Would call daemon API to create invite
    console.log("Creating invite for:", newPeerKey());
    setInviteToken("wop1://example-token");
  };

  const handleClaimInvite = async () => {
    if (!inviteToken()) return;
    // Would call daemon API to claim invite
    console.log("Claiming invite:", inviteToken());
  };

  // Create DOM
  const container = document.createElement("div");
  container.className = "p2p-plugin-ui";
  
  // Header
  const header = document.createElement("div");
  header.className = "flex items-center justify-between mb-4";
  header.innerHTML = `
    <h3 class="text-lg font-semibold">P2P Network</h3>
    <span class="px-2 py-1 rounded text-xs bg-blue-500/20 text-blue-400">
      ${peers().length} peers
    </span>
  `;
  container.appendChild(header);
  
  // Identity section
  const identitySection = document.createElement("div");
  identitySection.className = "mb-4 p-3 bg-wopr-panel rounded border border-wopr-border";
  identitySection.innerHTML = `
    <h4 class="text-sm font-semibold text-wopr-muted uppercase mb-2">Your Identity</h4>
    <div class="space-y-1 text-sm">
      <div class="flex justify-between">
        <span class="text-wopr-muted">Short ID:</span>
        <span class="font-mono">${identity()?.shortId || "Loading..."}</span>
      </div>
      <div class="flex justify-between">
        <span class="text-wopr-muted">Public Key:</span>
        <span class="font-mono text-xs">${identity()?.publicKey?.slice(0, 20) || "..."}...</span>
      </div>
    </div>
  `;
  container.appendChild(identitySection);
  
  // Peers list
  const peersSection = document.createElement("div");
  peersSection.className = "mb-4";
  
  const updatePeersList = () => {
    peersSection.innerHTML = "";
    
    const title = document.createElement("h4");
    title.className = "text-sm font-semibold text-wopr-muted uppercase mb-2";
    title.textContent = `Connected Peers (${peers().length})`;
    peersSection.appendChild(title);
    
    if (peers().length === 0) {
      peersSection.innerHTML += `
        <div class="text-sm text-wopr-muted p-3 bg-wopr-panel rounded border border-wopr-border">
          No peers connected. Add friends using their public key.
        </div>
      `;
    } else {
      const list = document.createElement("div");
      list.className = "space-y-2";
      
      peers().forEach(peer => {
        const item = document.createElement("div");
        item.className = "p-3 bg-wopr-panel rounded border border-wopr-border flex items-center justify-between";
        item.innerHTML = `
          <div>
            <div class="font-medium">${peer.name || peer.id.slice(0, 16)}...</div>
            <div class="text-sm text-wopr-muted">
              ${peer.sessions.length} session${peer.sessions.length !== 1 ? 's' : ''} shared
            </div>
          </div>
          <div class="flex items-center gap-2">
            <span class="w-2 h-2 rounded-full bg-green-500"></span>
            <button class="revoke-btn px-3 py-1 bg-red-500/20 text-red-400 rounded text-sm hover:bg-red-500/30">
              Revoke
            </button>
          </div>
        `;
        list.appendChild(item);
      });
      
      peersSection.appendChild(list);
    }
  };
  
  // Initial render and reactive updates
  const unsubscribe = peers(updatePeersList);
  updatePeersList();
  container.appendChild(peersSection);
  
  // Add peer form
  const addPeerSection = document.createElement("div");
  addPeerSection.className = "p-3 bg-wopr-panel rounded border border-wopr-border mb-4";
  addPeerSection.innerHTML = `
    <h4 class="text-sm font-semibold text-wopr-muted uppercase mb-3">Add Friend</h4>
    <div class="space-y-2">
      <input type="text" placeholder="Peer public key" class="peer-key-input w-full bg-wopr-bg border border-wopr-border rounded px-3 py-2 text-sm" />
      <input type="text" placeholder="Sessions to share (comma-separated, or * for all)" class="sessions-input w-full bg-wopr-bg border border-wopr-border rounded px-3 py-2 text-sm" />
      <button class="create-invite-btn w-full px-4 py-2 bg-wopr-accent text-wopr-bg rounded text-sm font-medium hover:bg-wopr-accent/90">
        Create Invite
      </button>
    </div>
  `;
  
  addPeerSection.querySelector(".peer-key-input").addEventListener("input", (e) => setNewPeerKey(e.target.value));
  addPeerSection.querySelector(".sessions-input").addEventListener("input", (e) => setSelectedSessions(e.target.value));
  addPeerSection.querySelector(".create-invite-btn").addEventListener("click", handleCreateInvite);
  
  container.appendChild(addPeerSection);
  
  // Claim invite form
  const claimSection = document.createElement("div");
  claimSection.className = "p-3 bg-wopr-panel rounded border border-wopr-border";
  claimSection.innerHTML = `
    <h4 class="text-sm font-semibold text-wopr-muted uppercase mb-3">Claim Invite</h4>
    <div class="space-y-2">
      <input type="text" placeholder="Invite token (wop1://...)" class="token-input w-full bg-wopr-bg border border-wopr-border rounded px-3 py-2 text-sm" />
      <button class="claim-btn w-full px-4 py-2 bg-green-500/20 text-green-400 rounded text-sm font-medium hover:bg-green-500/30">
        Claim Invite
      </button>
    </div>
  `;
  
  claimSection.querySelector(".token-input").addEventListener("input", (e) => setInviteToken(e.target.value));
  claimSection.querySelector(".claim-btn").addEventListener("click", handleClaimInvite);
  
  container.appendChild(claimSection);
  
  return container;
}
