// ── State ────────────────────────────────────────────────────────────────────

const state = {
  ws: null,
  packetCount: 0,
  totalBytes: 0,
  tunnels: new Set(),
  codecs: { hex: 0, base32: 0, base64: 0 },
  logIndex: 0,
};

// ── DOM refs (cached — avoid repeated querySelector) ────────────────────────

const $ = (sel) => document.querySelector(sel);

const dom = {
  status:       $('#status'),
  btnSend:      $('#btn-send'),
  btnCompare:   $('#btn-compare'),
  btnClear:     $('#btn-clear'),
  inputText:    $('#input-text'),
  tunnelPipe:   $('#tunnel-pipe'),
  packetStream: $('#packet-stream'),
  logBody:      $('#log-body'),
  comparePanel: $('#compare-panel'),
  statPackets:  $('#stat-packets'),
  statBytes:    $('#stat-bytes'),
  statTunnels:  $('#stat-tunnels'),
  packetCount:  $('#packet-count'),
  barHex:       $('#bar-hex'),
  barB32:       $('#bar-b32'),
  barB64:       $('#bar-b64'),
  pctHex:       $('#pct-hex'),
  pctB32:       $('#pct-b32'),
  pctB64:       $('#pct-b64'),
  barStandard:  $('#bar-standard'),
  barMutant:    $('#bar-mutant'),
};

// ── Batched rendering ───────────────────────────────────────────────────────
// Buffer incoming packets and flush to DOM once per animation frame.
// This prevents N reflows when N packets arrive in a burst.

let pendingPackets = [];
let rafScheduled = false;

function scheduleFlush() {
  if (!rafScheduled) {
    rafScheduled = true;
    requestAnimationFrame(flushPendingPackets);
  }
}

function flushPendingPackets() {
  rafScheduled = false;
  const batch = pendingPackets;
  pendingPackets = [];
  if (batch.length === 0) return;

  // Build all log rows in a DocumentFragment (single DOM insert)
  const frag = document.createDocumentFragment();
  for (const pkt of batch) {
    state.packetCount++;
    state.totalBytes += pkt.payload_size;
    state.tunnels.add(pkt.tunnel_id);
    state.codecs[pkt.codec] = (state.codecs[pkt.codec] || 0) + 1;

    animatePacket(pkt.codec);
    addChip(pkt);

    state.logIndex++;
    const tr = document.createElement('tr');
    tr.appendChild(createTd(String(state.logIndex)));
    tr.appendChild(createTdCode(pkt.tunnel_id));
    tr.appendChild(createTd(String(pkt.seq)));
    tr.appendChild(createTdBadge(pkt.codec));
    tr.appendChild(createTd(pkt.payload_size + 'B'));
    tr.appendChild(createTd(pkt.encoded_len + 'c'));
    tr.appendChild(createTdHex(pkt.payload_preview));
    frag.appendChild(tr);
  }

  // Prepend all new rows at once
  dom.logBody.prepend(frag);

  // Trim excess rows
  while (dom.logBody.children.length > 200) {
    dom.logBody.removeChild(dom.logBody.lastChild);
  }

  // Update stats once per frame, not per packet
  dom.statPackets.textContent = state.packetCount;
  dom.statBytes.textContent = formatBytes(state.totalBytes);
  dom.statTunnels.textContent = state.tunnels.size;
  dom.packetCount.textContent = state.packetCount + ' packets';
  updateCodecBars();
}

// ── Safe DOM builders (no innerHTML — prevents XSS) ─────────────────────────

function createTd(text) {
  const td = document.createElement('td');
  td.textContent = text;
  return td;
}

function createTdCode(text) {
  const td = document.createElement('td');
  const code = document.createElement('code');
  code.textContent = text;
  td.appendChild(code);
  return td;
}

function createTdBadge(codec) {
  const td = document.createElement('td');
  const span = document.createElement('span');
  span.className = 'codec-badge ' + codec;
  span.textContent = codec;
  td.appendChild(span);
  return td;
}

function createTdHex(hex) {
  const td = document.createElement('td');
  td.className = 'preview-hex';
  td.textContent = hex;
  return td;
}

// ── WebSocket ───────────────────────────────────────────────────────────────

function connect() {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  state.ws = new WebSocket(proto + '://' + location.host + '/ws');

  state.ws.onopen = function() {
    dom.status.textContent = 'Connected';
    dom.status.className = 'status connected';
    state.ws.send(JSON.stringify({ action: 'get_config' }));
  };

  state.ws.onclose = function() {
    dom.status.textContent = 'Disconnected';
    dom.status.className = 'status error';
    setTimeout(connect, 2000);
  };

  state.ws.onerror = function() {
    dom.status.textContent = 'Error';
    dom.status.className = 'status error';
  };

  state.ws.onmessage = function(e) {
    var msg = JSON.parse(e.data);
    handleMessage(msg);
  };
}

// ── Message handlers ────────────────────────────────────────────────────────

function handleMessage(msg) {
  switch (msg.type) {
    case 'packet':
      pendingPackets.push(msg);
      scheduleFlush();
      break;
    case 'transfer_started':
      dom.btnSend.disabled = true;
      dom.btnSend.textContent = 'Sending...';
      break;
    case 'transfer_complete':
      dom.btnSend.disabled = false;
      dom.btnSend.textContent = 'Send Through Tunnel';
      onTransferComplete(msg);
      break;
    case 'compare':
      showCompare(msg);
      break;
  }
}

// ── Packet visualization ────────────────────────────────────────────────────

function animatePacket(codec) {
  // Set CSS var so translateX knows the pipe width (GPU-only animation)
  var w = dom.tunnelPipe.offsetWidth;
  dom.tunnelPipe.style.setProperty('--pipe-width', w + 'px');

  var dot = document.createElement('div');
  dot.className = 'packet-dot ' + codec;
  dom.tunnelPipe.appendChild(dot);
  dot.addEventListener('animationend', function() { dot.remove(); });
}

function addChip(pkt) {
  var chip = document.createElement('span');
  chip.className = 'pkt-chip ' + pkt.codec;
  chip.textContent = pkt.codec + ':' + pkt.payload_size + 'B';
  dom.packetStream.appendChild(chip);

  while (dom.packetStream.children.length > 80) {
    dom.packetStream.removeChild(dom.packetStream.firstChild);
  }
}

function updateCodecBars() {
  var total = state.codecs.hex + state.codecs.base32 + state.codecs.base64;
  if (total === 0) return;

  var hPct = Math.round(state.codecs.hex / total * 100);
  var bPct = Math.round(state.codecs.base32 / total * 100);
  var xPct = Math.round(state.codecs.base64 / total * 100);

  dom.barHex.style.width = hPct + '%';
  dom.barB32.style.width = bPct + '%';
  dom.barB64.style.width = xPct + '%';
  dom.pctHex.textContent = hPct;
  dom.pctB32.textContent = bPct;
  dom.pctB64.textContent = xPct;
}

function formatBytes(b) {
  if (b < 1024) return b + 'B';
  if (b < 1048576) return (b / 1024).toFixed(1) + 'KB';
  return (b / 1048576).toFixed(1) + 'MB';
}

// ── Transfer complete ───────────────────────────────────────────────────────

function onTransferComplete(msg) {
  dom.btnSend.style.background = '#10b981';
  setTimeout(function() { dom.btnSend.style.background = ''; }, 1000);
}

// ── Comparison view ─────────────────────────────────────────────────────────

function showCompare(msg) {
  dom.comparePanel.style.display = 'block';

  var stdLen = msg.standard.total_len;
  var headerChars = 18;
  var stdHeaderPct = Math.min(Math.round(headerChars / stdLen * 100), 30);

  dom.barStandard.innerHTML =
    '<div class="byte-segment seg-header" style="width:' + stdHeaderPct + '%">HEADER</div>' +
    '<div class="byte-segment seg-payload" style="width:' + (100 - stdHeaderPct) + '%">payload data</div>';

  var mutHeaderPct = Math.max(5, Math.min(stdHeaderPct, 15));
  var beforePct = 75;
  var afterPct = 100 - beforePct - mutHeaderPct;

  dom.barMutant.innerHTML =
    '<div class="byte-segment seg-payload" style="width:' + beforePct + '%">payload data</div>' +
    '<div class="byte-segment seg-header" style="width:' + mutHeaderPct + '%">HDR</div>' +
    '<div class="byte-segment seg-payload" style="width:' + afterPct + '%">data</div>';

  dom.comparePanel.scrollIntoView({ behavior: 'smooth', block: 'center' });
}

// ── Event listeners ─────────────────────────────────────────────────────────

dom.btnSend.addEventListener('click', function() {
  var text = dom.inputText.value.trim();
  if (!text || !state.ws) return;

  state.ws.send(JSON.stringify({
    action: 'send',
    text: text,
    encoding: $('#opt-encoding').value,
    chunking: $('#opt-chunking').value,
    timing: $('#opt-timing').value,
  }));
});

dom.btnCompare.addEventListener('click', function() {
  if (!state.ws) return;
  var text = dom.inputText.value.trim() || 'secret exfiltrated data';
  state.ws.send(JSON.stringify({ action: 'demo_compare', text: text }));
});

dom.btnClear.addEventListener('click', function() {
  dom.logBody.innerHTML = '';
  dom.packetStream.innerHTML = '';
  state.logIndex = 0;
  state.packetCount = 0;
  state.totalBytes = 0;
  state.tunnels.clear();
  state.codecs = { hex: 0, base32: 0, base64: 0 };
  dom.statPackets.textContent = '0';
  dom.statBytes.textContent = '0';
  dom.statTunnels.textContent = '0';
  dom.packetCount.textContent = '0 packets';
  updateCodecBars();
});

dom.inputText.addEventListener('keydown', function(e) {
  if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
    dom.btnSend.click();
  }
});

// ── Init ────────────────────────────────────────────────────────────────────

connect();
