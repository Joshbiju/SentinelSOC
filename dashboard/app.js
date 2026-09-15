let trendChart = null;
let severityChart = null;

function $(id){
  return document.getElementById(id);
}

function esc(v){
  return String(v ?? "")
    .replace(/&/g,"&amp;")
    .replace(/</g,"&lt;")
    .replace(/>/g,"&gt;")
    .replace(/"/g,"&quot;")
    .replace(/'/g,"&#039;");
}

async function get(url){
  const r = await fetch(url);
  if(!r.ok) throw new Error("HTTP " + r.status);
  return r.json();
}

function setText(id,value){
  const el = $(id);
  if(el) el.textContent = value;
}

function setHTML(id,value){
  const el = $(id);
  if(el) el.innerHTML = value;
}

/* =========================
   SIDEBAR / TABS
   ========================= */

function showTab(name, button){
  document.querySelectorAll(".tab").forEach(el=>{
    el.classList.add("hidden");
  });

  const target = $(name);
  if(target) target.classList.remove("hidden");

  document.querySelectorAll(".nav").forEach(el=>{
    el.classList.remove("active");
  });

  if(button){
    button.classList.add("active");
  }else{
    const nav = document.querySelector(
      `.nav[onclick*="'${name}'"]`
    );
    if(nav) nav.classList.add("active");
  }
}

function setFilter(srcIp, threatType){
  const input = $("eventSearch");
  if(input) input.value = threatType || "";
  showTab("events");
  loadEvents(srcIp || "", threatType || "");
}

/* =========================
   DASHBOARD
   ========================= */


function openReports(){ loadReports(); }
async function dashboard(){
  try{
    const d = await get("/api/v2/dashboard");

    setText("score", (d.security_score ?? 0) + "%");
    setText("active", d.active_alerts ?? 0);
    setText("totalAlerts", d.total_alerts ?? 0);
    setText("totalEvents", d.live_events ?? 0);
    setText("uniqueIPs", d.unique_ips ?? 0);

    setHTML(
      "criticalText",
      `${d.critical ?? 0} Critical <em>▲ Live</em>`
    );

    setHTML(
      "resolvedText",
      `${d.resolved ?? 0} Resolved <em>▲ Live</em>`
    );

    setText(
      "priority",
      (d.critical ?? 0) + (d.high ?? 0)
    );

    setText("intelN", d.threat_intel ?? 0);

    const counts = d.top_vectors || [];

    setHTML(
      "attackTypes",
      counts.map(x=>
        `<div class="row clickable"
          onclick="setFilter('','${esc(x.vector)}')">
          <b>${esc(x.vector)}</b>
          <span>${x.count}</span>
        </div>`
      ).join("") ||
      '<div class="empty">Waiting for security events</div>'
    );

    await drawCharts();

  }catch(err){
    console.error("[SentinelSOC] dashboard:",err);
  }
}

/* =========================
   CHARTS
   ========================= */

async function drawCharts(){
  try{
    const tr = await get("/api/v2/trend");

    const labels = tr.map(x =>
      String(x.bucket || "").slice(11,16)
    );

    const vals = tr.map(x => x.count);

    const trendCanvas = $("trendChart");

    if(trendCanvas && typeof Chart !== "undefined"){
      if(trendChart) trendChart.destroy();

      trendChart = new Chart(trendCanvas,{
        type:"line",
        data:{
          labels,
          datasets:[{
            label:"Events",
            data:vals,
            tension:.25,
            pointRadius:3
          }]
        },
        options:{
          responsive:true,
          plugins:{
            legend:{display:false}
          },
          scales:{
            y:{beginAtZero:true}
          }
        }
      });
    }

    const alerts = await get("/api/v2/alerts");
    const sev = ["critical","high","medium","low"];
    const severityCanvas = $("severityChart");

    if(
      severityCanvas &&
      typeof Chart !== "undefined"
    ){
      if(severityChart) severityChart.destroy();

      severityChart = new Chart(severityCanvas,{
        type:"doughnut",
        data:{
          labels:sev,
          datasets:[{
            data:sev.map(
              s=>alerts.filter(x=>x.severity===s).length
            )
          }]
        },
        options:{
          plugins:{
            legend:{position:"bottom"}
          }
        }
      });
    }

  }catch(err){
    console.error("[SentinelSOC] charts:",err);
  }
}

/* =========================
   EVENTS
   ========================= */

async function loadEvents(srcIp="", threatType=""){
  try{
    let url="/api/v2/events?limit=180";

    if(srcIp)
      url += "&src_ip="+encodeURIComponent(srcIp);

    if(threatType)
      url += "&threat_type="+encodeURIComponent(threatType);

    const events = await get(url);

    const container = $("eventTable");
    if(!container) return;

    container.innerHTML =
      events.map(x=>`
        <div class="event">
          <b>${esc(x.event_type)}</b>
          <span class="badge ${esc(x.severity)}">
            ${esc(x.severity)}
          </span>
          <small>
            ${esc(x.timestamp)}
            · ${esc(x.src_ip || "local")}
            ${x.dst_port ? " · port " + esc(x.dst_port) : ""}
          </small>
          <p>${esc(x.message || x.raw || "")}</p>
        </div>
      `).join("") ||
      '<div class="empty">No telemetry events</div>';

  }catch(err){
    console.error("[SentinelSOC] events:",err);
  }
}

/* =========================
   ALERTS / L1 TRIAGE
   ========================= */

async function loadAlerts(){
  try{
    const alerts = await get("/api/v2/alerts?limit=150");

    setHTML(
      "alertTable",
      alerts.map(x=>`
        <div class="row alert-row">
          <div>
            <b class="${esc(x.severity)}">
              ${esc(x.title)}
            </b>

            <small>
              ${esc(x.created_at)}
              · Risk ${x.risk}
              · ${esc(x.technique || "Unclassified")}
              · Status: ${esc(x.status)}
            </small>

            <p>${esc(x.description)}</p>
          </div>

          <div class="actions">

            <button
              type="button"
              class="alert-action"
              data-alert-id="${x.id}"
              data-alert-status="acknowledged">
              Acknowledge
            </button>

            <button
              type="button"
              class="investigate-alert-action"
              data-alert-id="${x.id}">
              Investigate
            </button>

            <button
              type="button"
              class="incident-action"
              data-alert-id="${x.id}"
              onclick="makeIncident(${x.id})">
              Create Incident
            </button>

            <button
              type="button"
              class="alert-action"
              data-alert-id="${x.id}"
              data-alert-status="resolved">
              Resolve
            </button>

          </div>
        </div>
      `).join("") ||
      '<div class="empty">No alerts</div>'
    );

    const ips = {};

    alerts.forEach(x=>{
      if(x.event_id){
        ips[x.title]=(ips[x.title]||0)+1;
      }
    });

    setHTML(
      "sources",
      Object.entries(ips)
        .slice(0,8)
        .map(([k,v])=>`
          <div class="row">
            <b>${esc(k)}</b>
            <span>${v} alerts</span>
          </div>
        `).join("") ||
      '<div class="muted">No alerts yet.</div>'
    );

  }catch(err){
    console.error("[SentinelSOC] alerts:",err);
  }
}

async function setAlert(id,status){
  console.log(
    "[SentinelSOC] setAlert()",
    id,
    status
  );

  try{
    const r = await fetch(
      "/api/v2/alerts/" +
      encodeURIComponent(id) +
      "?status=" +
      encodeURIComponent(status),
      {
        method:"PATCH",
        headers:{
          "Accept":"application/json"
        }
      }
    );

    if(!r.ok){
      throw new Error(
        "HTTP " + r.status + " " + await r.text()
      );
    }

    const result = await r.json();

    console.log(
      "[SentinelSOC] ALERT UPDATED:",
      result
    );

    await loadAlerts();
    await dashboard();

  }catch(err){
    console.error(
      "[SentinelSOC] alert update failed:",
      err
    );

    alert("Alert update failed: " + err.message);
  }
}

/* =========================
   ALERT BUTTON HANDLER
   ========================= */

document.addEventListener("click",function(e){

  /* Alert status actions */
  const alertButton =
    e.target.closest(".alert-action");

  if(alertButton){
    e.preventDefault();
    e.stopPropagation();

    const id =
      Number(alertButton.dataset.alertId);

    const status =
      alertButton.dataset.alertStatus;

    setAlert(id,status);
    return;
  }

  /* Create Incident from alert */
  const incidentButton =
    e.target.closest(".incident-action");

  if(incidentButton){
    e.preventDefault();
    e.stopPropagation();

    const id =
      Number(incidentButton.dataset.alertId);

    console.log(
      "[SentinelSOC] INCIDENT BUTTON CLICKED:",
      id
    );

    makeIncident(id);
    return;
  }

},true);

/* =========================
   INCIDENTS
   ========================= */

async function makeIncident(alertId){
  console.log("[SentinelSOC] Create Incident from alert:", alertId);

  try{
    const r = await fetch("/api/v2/incidents",{
      method:"POST",
      headers:{
        "Content-Type":"application/json",
        "Accept":"application/json"
      },
      body:JSON.stringify({
        title:"L1 investigation — alert #" + alertId,
        severity:"high",
        risk:80,
        summary:"Incident created from SentinelSOC alert triage.",
        owner:"SOC Analyst",
        alert_id:Number(alertId)
      })
    });

    const text = await r.text();

    console.log(
      "[SentinelSOC] Incident response:",
      r.status,
      text
    );

    if(!r.ok){
      throw new Error(
        "HTTP " + r.status + ": " + text
      );
    }

    const result = JSON.parse(text);

    console.log(
      "[SentinelSOC] Incident created:",
      result
    );

    showTab("incidents");

    await new Promise(
      resolve => setTimeout(resolve,100)
    );

    await loadIncidents();

    return result;

  }catch(err){

    console.error(
      "[SentinelSOC] Create Incident failed:",
      err
    );

    alert(
      "Create Incident failed:\n\n" + err.message
    );

    return null;
  }
}

async function loadIncidents(){
  try{
    console.log("[SentinelSOC] Loading incidents...");

    const incidents = await get("/api/v2/incidents");
    const board = $("incidentBoard");

    if(!board){
      console.error("[SentinelSOC] incidentBoard not found");
      return;
    }

    const statuses = [
      ["open","OPEN"],
      ["investigating","INVESTIGATING"],
      ["contained","CONTAINED"],
      ["closed","RESOLVED"]
    ];

    let html = "";

    for(const pair of statuses){
      const status = pair[0];
      const title = pair[1];

      const items = incidents.filter(function(x){
        return String(x.status || "open").toLowerCase() === status;
      });

      let cards = "";

      if(items.length === 0){
        cards = '<div class="muted">No incidents</div>';
      }else{
        for(const x of items){

          let actions = "";

          if(status !== "investigating"){
            actions +=
              '<button type="button" class="incident-status-action" data-incident-id="' +
              Number(x.id) +
              '" data-incident-status="investigating">Investigate</button>';
          }

          actions +=
            '<button type="button" class="incident-view-action" data-incident-id="' +
            Number(x.id) +
            '">View Investigation</button>';

          if(status !== "contained"){
            actions +=
              '<button type="button" class="incident-status-action" data-incident-id="' +
              Number(x.id) +
              '" data-incident-status="contained">Contain</button>';
          }

          if(status !== "closed"){
            actions +=
              '<button type="button" class="incident-status-action" data-incident-id="' +
              Number(x.id) +
              '" data-incident-status="closed">Resolve</button>';
          }

          cards +=
            '<div class="ticket" draggable="true" data-incident-id="' +
            Number(x.id) +
            '">' +
              '<b>' + esc(x.title) + '</b>' +
              '<small>' +
                esc(x.severity || "high") +
                ' · Risk ' +
                String(x.risk ?? 0) +
                ' · ' +
                esc(x.owner || "SOC Analyst") +
              '</small>' +
              '<p>' + esc(x.summary || "") + '</p>' +
              '<div class="actions">' +
                actions +
              '</div>' +
            '</div>';
        }
      }

      html +=
        '<div class="kanban-col" data-status="' +
        status +
        '">' +
          '<h3>' +
            title +
            ' (' +
            items.length +
            ')' +
          '</h3>' +
          '<div class="dropzone">' +
            cards +
          '</div>' +
        '</div>';
    }

    board.innerHTML = html;

    console.log(
      "[SentinelSOC] Incidents rendered:",
      incidents.length
    );

  }catch(err){
    console.error(
      "[SentinelSOC] incidents:",
      err
    );
  }
}


document.addEventListener("click",function(e){
  const button = e.target.closest(".incident-status-action");

  if(!button){
    return;
  }

  e.preventDefault();
  e.stopPropagation();

  const id = Number(button.dataset.incidentId);
  const status = button.dataset.incidentStatus;

  console.log(
    "[SentinelSOC] Incident status:",
    id,
    status
  );

  setIncidentStatus(id,status);
},true);

async function setIncidentStatus(id,status){
  try{
    const r = await fetch(
      "/api/v2/incidents/" +
      encodeURIComponent(id) +
      "?status=" +
      encodeURIComponent(status),
      {
        method:"PATCH"
      }
    );

    if(!r.ok){
      throw new Error(
        "HTTP " + r.status
      );
    }

    await loadIncidents();
    await dashboard();

  }catch(err){
    console.error(
      "[SentinelSOC] incident status:",
      err
    );
  }
}


/* =========================
   L1 INVESTIGATION WORKSPACE
   ========================= */

function ensureInvestigationModal(){
  if($("investigationModal")) return;

  const div = document.createElement("div");

  div.id = "investigationModal";

  div.innerHTML = `
    <div class="investigation-backdrop">
      <div class="investigation-modal">

        <div class="investigation-header">
          <div>
            <span class="muted">SENTINELSOC · L1 INVESTIGATION</span>
            <h2 id="investigationTitle">Investigation</h2>
          </div>

          <button
            type="button"
            class="investigation-close"
            onclick="closeInvestigation()">
            ×
          </button>
        </div>

        <div id="investigationContent">
          <div class="muted">Loading investigation...</div>
        </div>

      </div>
    </div>
  `;

  document.body.appendChild(div);
}

function closeInvestigation(){
  const modal = $("investigationModal");
  if(modal) modal.remove();
}

function eventIcon(type){
  const icons = {
    login_failed:"🔴",
    login_success:"🟢",
    privilege_change:"🟠",
    account_change:"🟠",
    network_connection:"🔵",
    port_scan:"🟣"
  };

  return icons[String(type || "").toLowerCase()] || "•";
}

function formatEventTime(timestamp){
  if(!timestamp) return "--:--:--";

  const d = new Date(timestamp);

  if(Number.isNaN(d.getTime()))
    return String(timestamp);

  return d.toLocaleTimeString([], {
    hour:"2-digit",
    minute:"2-digit",
    second:"2-digit",
    hour12:false
  });
}

function investigationTimeline(events){
  if(!events || !events.length){
    return `
      <div class="investigation-empty">
        No related security telemetry was found.
      </div>
    `;
  }

  return events.map(e => `
    <div class="timeline-item">
      <div class="timeline-time">
        ${esc(formatEventTime(e.timestamp))}
      </div>

      <div class="timeline-marker">
        ${eventIcon(e.event_type)}
      </div>

      <div class="timeline-event">
        <b>${esc(e.event_type || "event")}</b>

        <span>
          ${esc(e.user || "")}
          ${e.src_ip ? " · " + esc(e.src_ip) : ""}
          ${e.dst_ip ? " → " + esc(e.dst_ip) : ""}
          ${e.dst_port ? ":" + esc(e.dst_port) : ""}
        </span>

        <small>
          ${esc(e.message || e.process || e.command || "")}
        </small>
      </div>
    </div>
  `).join("");
}

function indicator(value,label){
  return `
    <div class="investigation-indicator ${value ? "detected" : "not-detected"}">
      <span>${value ? "●" : "○"}</span>
      <b>${esc(label)}</b>
      <small>${value ? "Detected" : "Not observed"}</small>
    </div>
  `;
}

async function openAlertInvestigation(id){
  ensureInvestigationModal();

  const content = $("investigationContent");

  content.innerHTML =
    '<div class="muted">Loading real telemetry...</div>';

  try{
    const data =
      await get(
        "/api/v2/alerts/" +
        encodeURIComponent(id) +
        "/investigation"
      );

    const a = data.alert || {};
    const indicators = data.indicators || {};
    const users = data.users || [];

    setText(
      "investigationTitle",
      "Alert #" + id + " — Investigation"
    );

    content.innerHTML = `
      <div class="investigation-summary">

        <div class="investigation-card primary">
          <span>SEVERITY</span>
          <strong class="${esc(a.severity || "high")}">
            ${esc((a.severity || "high").toUpperCase())}
          </strong>
        </div>

        <div class="investigation-card">
          <span>RISK</span>
          <strong>${esc(a.risk || 0)}</strong>
        </div>

        <div class="investigation-card">
          <span>SOURCE IP</span>
          <strong>${esc(data.source_ip || "Unknown")}</strong>
        </div>

        <div class="investigation-card">
          <span>TECHNIQUE</span>
          <strong>${esc(a.technique || "Unclassified")}</strong>
        </div>

      </div>

      <div class="investigation-section">
        <h3>Alert Details</h3>

        <div class="detail-grid">
          <div>
            <span>Title</span>
            <b>${esc(a.title || "")}</b>
          </div>

          <div>
            <span>Tactic</span>
            <b>${esc(a.tactic || "Unclassified")}</b>
          </div>

          <div>
            <span>Status</span>
            <b>${esc(a.status || "new")}</b>
          </div>

          <div>
            <span>Username</span>
            <b>${esc(users.join(", ") || "Unknown")}</b>
          </div>

          <div class="detail-wide">
            <span>Description</span>
            <b>${esc(a.description || "")}</b>
          </div>
        </div>
      </div>

      <div class="investigation-section">
        <h3>Investigation Indicators</h3>

        <div class="indicator-grid">
          ${indicator(
            Number(indicators.failed_logins || 0) > 0,
            (indicators.failed_logins || 0) +
            " failed authentication attempts"
          )}

          ${indicator(
            indicators.successful_login,
            "Successful login"
          )}

          ${indicator(
            indicators.privilege_change,
            "Privilege change"
          )}

          ${indicator(
            indicators.network_connection,
            "Outbound network connection"
          )}

          ${indicator(
            indicators.account_change,
            "Account modification"
          )}
        </div>
      </div>

      <div class="investigation-section">
        <div class="investigation-section-head">
          <h3>Related Activity Timeline</h3>
          <span class="muted">
            ${data.timeline.length} real events
          </span>
        </div>

        <div class="investigation-timeline">
          ${investigationTimeline(data.timeline)}
        </div>
      </div>

      <div class="investigation-actions">
        <button
          type="button"
          onclick="closeInvestigation()">
          Close Investigation
        </button>

        <button
          type="button"
          class="primary-action"
          onclick="closeInvestigation(); makeIncident(${id})">
          Create Incident
        </button>
      </div>
    `;

  }catch(err){

    console.error(
      "[SentinelSOC] alert investigation:",
      err
    );

    content.innerHTML =
      '<div class="empty">Unable to load investigation data.</div>';
  }
}

async function openIncidentInvestigation(id){
  ensureInvestigationModal();

  const content = $("investigationContent");

  content.innerHTML =
    '<div class="muted">Loading incident telemetry...</div>';

  try{
    const data =
      await get(
        "/api/v2/incidents/" +
        encodeURIComponent(id) +
        "/investigation"
      );

    const incident = data.incident || {};
    const indicators = data.indicators || {};

    setText(
      "investigationTitle",
      "Incident #" + id + " — Investigation"
    );

    content.innerHTML = `
      <div class="investigation-summary">

        <div class="investigation-card primary">
          <span>SEVERITY</span>
          <strong class="${esc(incident.severity || "high")}">
            ${esc((incident.severity || "high").toUpperCase())}
          </strong>
        </div>

        <div class="investigation-card">
          <span>RISK</span>
          <strong>${esc(incident.risk || 0)}</strong>
        </div>

        <div class="investigation-card">
          <span>STATUS</span>
          <strong>${esc(incident.status || "open")}</strong>
        </div>

        <div class="investigation-card">
          <span>SOURCE IP</span>
          <strong>${esc(
            (data.source_ips || []).join(", ") || "Unknown"
          )}</strong>
        </div>

      </div>

      <div class="investigation-section">
        <h3>Incident Summary</h3>

        <div class="detail-grid">

          <div class="detail-wide">
            <span>Title</span>
            <b>${esc(incident.title || "")}</b>
          </div>

          <div>
            <span>Owner</span>
            <b>${esc(incident.owner || "SOC Analyst")}</b>
          </div>

          <div>
            <span>Status</span>
            <b>${esc(incident.status || "open")}</b>
          </div>

          <div class="detail-wide">
            <span>Summary</span>
            <b>${esc(incident.summary || "")}</b>
          </div>

        </div>
      </div>

      <div class="investigation-section">
        <h3>Investigation Indicators</h3>

        <div class="indicator-grid">

          ${indicator(
            Number(indicators.failed_logins || 0) > 0,
            (indicators.failed_logins || 0) +
            " failed authentication attempts"
          )}

          ${indicator(
            indicators.successful_login,
            "Successful login"
          )}

          ${indicator(
            indicators.privilege_change,
            "Privilege change"
          )}

          ${indicator(
            indicators.network_connection,
            "Outbound network connection"
          )}

          ${indicator(
            indicators.account_change,
            "Account modification"
          )}

        </div>
      </div>

      <div class="investigation-section">
        <div class="investigation-section-head">
          <h3>Related Activity Timeline</h3>
          <span class="muted">
            ${data.timeline.length} real events
          </span>
        </div>

        <div class="investigation-timeline">
          ${investigationTimeline(data.timeline)}
        </div>
      </div>

      <div class="investigation-section">
        <h3>Linked Alerts</h3>

        <div class="linked-alerts">
          ${(data.alerts || []).map(a => `
            <div class="linked-alert">
              <b>${esc(a.title || "")}</b>
              <span>
                #${esc(a.id)}
                · ${esc(a.severity || "high")}
                · Risk ${esc(a.risk || 0)}
              </span>
            </div>
          `).join("") || '<div class="muted">No linked alerts.</div>'}
        </div>
      </div>

      <div class="investigation-actions">

        <button
          type="button"
          onclick="closeInvestigation()">
          Close Investigation
        </button>

        <button
          type="button"
          class="primary-action"
          onclick="setIncidentStatus(${Number(id)} ,'contained'); closeInvestigation();">
          Contain
        </button>

        <button
          type="button"
          class="danger-action"
          onclick="setIncidentStatus(${Number(id)} ,'closed'); closeInvestigation();">
          Resolve
        </button>

      </div>
    `;

  }catch(err){

    console.error(
      "[SentinelSOC] incident investigation:",
      err
    );

    content.innerHTML =
      '<div class="empty">Unable to load incident investigation.</div>';
  }
}

document.addEventListener("click",function(e){

  const alertButton =
    e.target.closest(".investigate-alert-action");

  if(alertButton){
    e.preventDefault();
    e.stopPropagation();

    openAlertInvestigation(
      Number(alertButton.dataset.alertId)
    );

    return;
  }

  const incidentButton =
    e.target.closest(".incident-view-action");

  if(incidentButton){
    e.preventDefault();
    e.stopPropagation();

    openIncidentInvestigation(
      Number(incidentButton.dataset.incidentId)
    );
  }

},true);


/* =========================
   ASSETS
   ========================= */

async function loadAssets(){
  try{
    const assets = await get("/api/v2/assets");

    const container =
      $("assetTable") || $("assetsList");

    if(!container) return;

    if(!assets.length){
      container.innerHTML =
        '<div class="empty">No monitored assets</div>';
      return;
    }

    container.innerHTML = `
      <div class="asset-grid">
        ${assets.map(x=>{
          const risk = Number(x.risk || 0);

          let riskClass = "low";
          if(risk >= 70) riskClass = "high";
          else if(risk >= 40) riskClass = "medium";

          const statusClass =
            String(x.status || "").toLowerCase() === "online"
              ? "online"
              : "offline";

          const lastSeen = x.last_seen
            ? new Date(x.last_seen).toLocaleString()
            : "Never";

          return `
            <div class="asset-card">

              <div class="asset-card-head">
                <div>
                  <div class="asset-host">
                    <span class="asset-icon">▣</span>
                    ${esc(x.hostname)}
                  </div>
                  <div class="asset-os">
                    ${esc(x.os || "Unknown OS")}
                  </div>
                </div>

                <span class="asset-status ${statusClass}">
                  ${esc(x.status || "unknown")}
                </span>
              </div>

              <div class="asset-collection">
                <span>COLLECTION</span>
                <b>${esc(x.collection || "Unknown")}</b>
              </div>

              <div class="asset-stats">

                <div class="asset-stat">
                  <span>EVENTS</span>
                  <b>${Number(x.event_count || 0).toLocaleString()}</b>
                </div>

                <div class="asset-stat">
                  <span>ALERTS</span>
                  <b>${Number(x.alert_count || 0).toLocaleString()}</b>
                </div>

                <div class="asset-stat">
                  <span>RISK</span>
                  <b class="risk-${riskClass}">
                    ${risk}
                  </b>
                </div>

              </div>

              <div class="asset-last-seen">
                <span>LAST TELEMETRY</span>
                <b>${esc(lastSeen)}</b>
              </div>

            </div>
          `;
        }).join("")}
      </div>
    `;

  }catch(err){
    console.error("[SentinelSOC] assets:",err);
  }
}

/* =========================
   THREAT INTEL
   ========================= */


async function loadIntel(){
  try{
    const iocs = await get("/api/v2/iocs");
    const correlation = await get("/api/v2/threat-intel/correlation");

    const search = (($("intelSearch")?.value || "")).toLowerCase();
    const type = $("intelType")?.value || "";
    const severity = $("intelSeverity")?.value || "";

    const filtered = (iocs || []).filter(x=>{
      const hay = [
        x.kind,
        x.value,
        x.severity,
        x.description
      ].join(" ").toLowerCase();

      return (!search || hay.includes(search))
        && (!type || x.kind === type)
        && (!severity || x.severity === severity);
    });

    const count = $("iocCount");
    if(count) count.textContent = filtered.length + " indicators";

    const table = $("iocTable");

    if(table){
      table.innerHTML = filtered.map(x=>`
        <div class="row intel-ioc-row">
          <div>
            <b class="${esc(x.severity || "medium")}">
              ${esc((x.kind || "IOC").toUpperCase())}
            </b>
            <strong class="ioc-value">${esc(x.value)}</strong>
            <small>${esc(x.description || "No description")}</small>
          </div>
          <div class="ioc-meta">
            <span>${esc(x.severity || "medium")}</span>
            <button onclick="event.stopPropagation();removeIOC(${x.id})">
              Remove
            </button>
          </div>
        </div>
      `).join("") || '<div class="empty">No matching indicators</div>';
    }

    const container = $("intelTable");

    if(container){
      container.innerHTML = (correlation || []).map(x=>`
        <div class="row intel-correlation">
          <div>
            <b>${esc(x.source_ip)}</b>
            <small>
              ${x.events} observed events
              · ${x.destination_ports?.length || 0} destination ports
            </small>
          </div>

          <div>
            <span class="badge">
              ${esc((x.threat_types || []).join(", ") || "Observed")}
            </span>
          </div>
        </div>
      `).join("") || '<div class="empty">No source IP correlation data</div>';
    }

  }catch(err){
    console.error("Threat Intel error:",err);
  }
}


async function addIOC(){
  const kind = $("iocKind")?.value || "ip";
  const value = ($("iocValue")?.value || "").trim();
  const severity = $("iocSeverity")?.value || "medium";
  const description = ($("iocDescription")?.value || "").trim();

  if(!value){
    alert("Enter an IOC value.");
    return;
  }

  try{
    const response = await fetch("/api/v2/iocs",{
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({
        kind,
        value,
        severity,
        description
      })
    });

    if(!response.ok){
      throw new Error(await response.text());
    }

    $("iocValue").value = "";
    $("iocDescription").value = "";

    await loadIntel();

  }catch(err){
    console.error(err);
    alert("Unable to add IOC.");
  }
}


async function removeIOC(id){
  if(!confirm("Remove this IOC from the local intelligence repository?")){
    return;
  }

  try{
    const response = await fetch("/api/v2/iocs/" + id,{
      method:"DELETE"
    });

    if(!response.ok){
      throw new Error(await response.text());
    }

    await loadIntel();

  }catch(err){
    console.error(err);
    alert("IOC removal is not available yet.");
  }
}

async function loadBlocked(){
  try{
    const rows =
      await get("/api/v2/ip-management");

    const container =
      $("blockedTable") || $("blockedList");

    if(!container) return;

    container.innerHTML =
      rows.map(x=>`
        <div class="row">
          <div>
            <b>${esc(x.ip)}</b>
            <small>${esc(x.reason || "")}</small>
          </div>

          <button
            type="button"
            onclick="unblockIP('${esc(x.ip)}')">
            Unblock
          </button>
        </div>
      `).join("") ||
      '<div class="empty">No blocked IPs</div>';

  }catch(err){
    console.error("[SentinelSOC] blocked:",err);
  }
}

async function blockIP(ip,reason){
  try{
    await fetch(
      "/api/v2/ip-management/" +
      encodeURIComponent(ip) +
      "/block",
      {
        method:"POST",
        headers:{
          "Content-Type":"application/json"
        },
        body:JSON.stringify({
          reason:reason ||
            "Manual SOC analyst block"
        })
      }
    );

    await loadBlocked();

  }catch(err){
    console.error("[SentinelSOC] block:",err);
  }
}

async function unblockIP(ip){
  try{
    await fetch(
      "/api/v2/ip-management/" +
      encodeURIComponent(ip) +
      "/unblock",
      {
        method:"POST"
      }
    );

    await loadBlocked();

  }catch(err){
    console.error("[SentinelSOC] unblock:",err);
  }
}

/* =========================
   BRUTE FORCE POPUP
   DO NOT CHANGE — EXACTLY 5 SEC
   ========================= */

function flashBrute(a){
  const text = $("flashText");

  if(text){
    text.textContent =
      `${a.description ||
        "5 failed SSH attempts from one source IP within 60 seconds"} · T1110 Brute Force`;
  }

  const flash = $("flash");

  if(!flash) return;

  flash.classList.remove("hidden");

  clearTimeout(window.bruteTimer);

  window.bruteTimer =
    setTimeout(
      ()=>flash.classList.add("hidden"),
      5000
    );
}

/* =========================
   WEBSOCKET
   ========================= */

function connect(){
  const protocol =
    location.protocol === "https:"
      ? "wss"
      : "ws";

  const ws =
    new WebSocket(
      protocol +
      "://" +
      location.host +
      "/ws"
    );

  ws.onopen = ()=>{
    console.log(
      "[SentinelSOC] WebSocket connected"
    );
  };

  ws.onclose = ()=>{
    console.log(
      "[SentinelSOC] WebSocket disconnected"
    );

    setTimeout(connect,1500);
  };

  ws.onerror = err=>{
    console.error(
      "[SentinelSOC] WebSocket:",
      err
    );
  };

  ws.onmessage = e=>{
    try{
      const d = JSON.parse(e.data);

      if(d.type === "event"){
        loadEvents();
        dashboard();

        if(d.alerts?.length){
          d.alerts.forEach(a=>{
            loadAlerts();

            if(a.rule_id === "CORR-001"){
              flashBrute(a);
            }
          });
        }
      }

      if(d.type === "alert"){
        loadAlerts();
        dashboard();

        if(d.data?.rule_id === "CORR-001"){
          flashBrute(d.data);
        }
      }

    }catch(err){
      console.error(
        "[SentinelSOC] WebSocket message:",
        err
      );
    }
  };
}


async function createIncident(){

  console.log(
    "[SentinelSOC] + New Incident clicked"
  );

  const title =
    window.prompt(
      "Incident title:",
      "Manual SOC investigation"
    );

  if(title === null){
    return;
  }

  const summary =
    window.prompt(
      "Incident summary:",
      "Manually created L1 SOC investigation."
    );

  if(summary === null){
    return;
  }

  try{

    const r = await fetch(
      "/api/v2/incidents",
      {
        method:"POST",
        headers:{
          "Content-Type":"application/json",
          "Accept":"application/json"
        },
        body:JSON.stringify({
          title:
            title.trim() ||
            "Manual SOC investigation",
          severity:"high",
          risk:70,
          summary:
            summary.trim() ||
            "Manually created L1 SOC investigation.",
          owner:"SOC Analyst",
          alert_id:null
        })
      }
    );

    const text =
      await r.text();

    console.log(
      "[SentinelSOC] Manual incident response:",
      r.status,
      text
    );

    if(!r.ok){
      throw new Error(
        "HTTP " + r.status + ": " + text
      );
    }

    const result =
      JSON.parse(text);

    console.log(
      "[SentinelSOC] Manual incident created:",
      result
    );

    showTab("incidents");

    await new Promise(
      resolve => setTimeout(resolve,100)
    );

    await loadIncidents();

  }catch(err){

    console.error(
      "[SentinelSOC] Manual incident failed:",
      err
    );

    alert(
      "New Incident failed:\n\n" + err.message
    );
  }
}

window.createIncident = createIncident;
window.makeIncident = makeIncident;

/* =========================
   REFRESH
   ========================= */


async function loadReports(){
  try{
    const dashboardData =
      await get("/api/v2/dashboard");

    const alerts =
      await get("/api/v2/alerts?limit=150");

    const incidents =
      await get("/api/v2/incidents");

    const iocs =
      await get("/api/v2/iocs");

    const events =
      await get("/api/v2/events?limit=150");

    const securityEvents =
      (events || []).filter(x =>
        ![
          "system_metrics",
          "network_inventory",
          "process_inventory"
        ].includes(x.event_type)
      );

    const active =
      (alerts || []).filter(x =>
        !["resolved", "closed"].includes(
          String(x.status || "").toLowerCase()
        )
      );

    const resolved =
      (alerts || []).filter(x =>
        ["resolved", "closed"].includes(
          String(x.status || "").toLowerCase()
        )
      );

    const priority =
      (alerts || []).filter(x =>
        ["critical","high"].includes(
          String(x.severity || "").toLowerCase()
        )
      );

    setText(
      "reportEvents",
      dashboardData.live_events ?? securityEvents.length
    );

    setText(
      "reportAlerts",
      dashboardData.total_alerts ?? alerts.length
    );

    setText(
      "reportActive",
      dashboardData.active_alerts ?? active.length
    );

    setText(
      "reportResolved",
      dashboardData.resolved ?? resolved.length
    );

    setText(
      "reportPriority",
      dashboardData.critical != null &&
      dashboardData.high != null
        ? Number(dashboardData.critical) +
          Number(dashboardData.high)
        : priority.length
    );

    setText(
      "reportIntel",
      iocs.length
    );

    // Event distribution
    const eventCounts = {};

    securityEvents.forEach(x=>{
      const key = x.event_type || "unknown";
      eventCounts[key] =
        (eventCounts[key] || 0) + 1;
    });

    const eventRows =
      Object.entries(eventCounts)
      .sort((a,b)=>b[1]-a[1])
      .slice(0,10);

    $("reportEventTypes").innerHTML =
      eventRows.map(([k,v])=>`
        <div class="row report-row">
          <b>${esc(k)}</b>
          <span>${v}</span>
        </div>
      `).join("")
      || '<div class="empty">No security events</div>';

    // Severity
    const severityCounts = {};

    (alerts || []).forEach(x=>{
      const key =
        String(x.severity || "unknown").toLowerCase();

      severityCounts[key] =
        (severityCounts[key] || 0) + 1;
    });

    $("reportSeverity").innerHTML =
      Object.entries(severityCounts)
      .sort((a,b)=>b[1]-a[1])
      .map(([k,v])=>`
        <div class="row report-row">
          <b class="${esc(k)}">${esc(k)}</b>
          <span>${v}</span>
        </div>
      `).join("")
      || '<div class="empty">No alerts</div>';

    // Techniques
    const techniqueCounts = {};

    (alerts || []).forEach(x=>{
      const key =
        x.technique || "Unclassified";

      techniqueCounts[key] =
        (techniqueCounts[key] || 0) + 1;
    });

    $("reportTechniques").innerHTML =
      Object.entries(techniqueCounts)
      .sort((a,b)=>b[1]-a[1])
      .slice(0,10)
      .map(([k,v])=>`
        <div class="row report-row">
          <b>${esc(k)}</b>
          <span>${v}</span>
        </div>
      `).join("")
      || '<div class="empty">No techniques observed</div>';

    // Source IPs
    const sourceCounts = {};

    securityEvents.forEach(x=>{
      if(x.src_ip){
        sourceCounts[x.src_ip] =
          (sourceCounts[x.src_ip] || 0) + 1;
      }
    });

    $("reportSources").innerHTML =
      Object.entries(sourceCounts)
      .sort((a,b)=>b[1]-a[1])
      .slice(0,10)
      .map(([k,v])=>`
        <div class="row report-row">
          <b>${esc(k)}</b>
          <span>${v} events</span>
        </div>
      `).join("")
      || '<div class="empty">No source IPs observed</div>';

    // Recent alerts
    $("reportRecentAlerts").innerHTML =
      (alerts || []).slice(0,10).map(x=>`
        <div class="row report-alert-row">
          <div>
            <b class="${esc(x.severity || "medium")}">
              ${esc(x.title || "Alert")}
            </b>
            <small>
              ${esc(x.created_at || "")}
              · Risk ${x.risk ?? 0}
              · ${esc(x.technique || "Unclassified")}
            </small>
          </div>

          <span class="${esc(x.status || "new")}">
            ${esc(x.status || "new")}
          </span>
        </div>
      `).join("")
      || '<div class="empty">No alerts</div>';

  }catch(err){
    console.error("Reports error:",err);
  }
}


async function loadSettings(){
  try{
    const response = await fetch("/api/v2/dashboard");

    if(!response.ok){
      throw new Error("Backend unavailable");
    }

    const d = await response.json();

    const backend = $("settingBackend");
    const database = $("settingDatabase");

    if(backend){
      backend.textContent = "● Online";
      backend.className = "status-good";
    }

    if(database){
      database.textContent = "● Connected";
      database.className = "status-good";
    }

    /*
     * The values below mirror the active SentinelSOC
     * detection configuration.
     *
     * Brute force:
     *   5 attempts / 60 seconds
     *
     * Port scan:
     *   configured by backend collector
     */

    const threshold = $("settingPortThreshold");
    if(threshold){
      threshold.textContent = "8 unique ports";
    }

    const cooldown = $("settingCooldown");
    if(cooldown){
      cooldown.textContent = "Configured by detection engine";
    }

  }catch(err){

    console.error("Settings error:", err);

    const backend = $("settingBackend");

    if(backend){
      backend.textContent = "● Offline";
      backend.className = "status-bad";
    }
  }
}

async function refresh(){
  await Promise.allSettled([
    dashboard(),
    loadEvents(),
    loadAlerts(),
    loadIncidents(),
    loadAssets(),
    loadIntel(),
    loadBlocked(),
    loadSettings(),
    loadReports()
  ]);
}

/* =========================
   START
   ========================= */

document.addEventListener("DOMContentLoaded",()=>{
  const active =
    document.querySelector(".nav.active");

  showTab(
    "overview",
    active
  );

  refresh();
  connect();

  setInterval(()=>{
    dashboard();
    loadAlerts();
  },5000);
});


/* ============================================================
   COMMAND GUARD
   ============================================================ */


async function toggleCommandGuard(){
  try{
    const current = await get("/api/v2/command-guard");
    const enabled = !!(current.status && current.status.enabled);

    const r = await fetch("/api/v2/command-guard", {
      method: "PATCH",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({enabled: !enabled})
    });

    if(!r.ok) throw new Error("HTTP " + r.status);

    await loadCommandGuard();
  }catch(err){
    console.error("Command Guard toggle error:", err);
    alert("Unable to change Command Guard status.");
  }
}

async function loadCommandGuard(){
  try{
    const data = await get("/api/v2/command-guard");
    const status = data.status || {};
    const events = data.events || [];

    const allowlist = await get("/api/v2/command-guard/allowlist");

    const enabled = !!status.enabled;

    const toggle = document.getElementById("commandGuardToggle");
    const state = document.getElementById("guardProtectionState");
    const count = document.getElementById("guardBlockedCount");
    const list = document.getElementById("commandGuardEvents");
    const allowListEl = document.getElementById("commandGuardAllowlist");

    if(toggle){
      toggle.textContent = enabled ? "● PROTECTION ON" : "○ PROTECTION OFF";
      toggle.classList.toggle("guard-on", enabled);
      toggle.classList.toggle("guard-off", !enabled);
    }

    if(state){
      state.textContent = enabled ? "ACTIVE" : "DISABLED";
      state.classList.toggle("guard-active", enabled);
    }

    if(count){
      count.textContent = events.filter(x => x.blocked).length;
    }

    if(list){
      if(!events.length){
        list.innerHTML =
          '<div class="muted">No suspicious commands have been recorded.</div>';
      }else{
        list.innerHTML = events.map((x, index) => {
          const command = x.command || "Unknown command";
          const blocked = !!x.blocked;

          return `
            <div class="guard-event">
              <div class="guard-event-main">
                <strong class="guard-command">${esc(command)}</strong>
                <span>${esc(x.reason || "Suspicious command")}</span>
                <small>${esc(x.timestamp || "")}</small>
              </div>

              <div class="guard-event-meta">
                <b class="${blocked ? "guard-blocked" : "guard-detected"}">
                  ${blocked ? "BLOCKED" : "DETECTED"}
                </b>

                ${blocked ? `
                  <button
                    type="button"
                    class="guard-allow-btn"
                    onclick="allowGuardCommand(${JSON.stringify(command)})">
                    ALLOW
                  </button>
                ` : ""}
              </div>
            </div>
          `;
        }).join("");
      }
    }

    if(allowListEl){
      if(!allowlist.length){
        allowListEl.innerHTML =
          '<div class="muted">No commands have been explicitly allowed.</div>';
      }else{
        allowListEl.innerHTML = allowlist.map(command => `
          <div class="guard-event guard-allowed-event">
            <div class="guard-event-main">
              <strong class="guard-command">${esc(command)}</strong>
              <span>Explicitly allowed by SOC analyst</span>
            </div>

            <div class="guard-event-meta">
              <b class="guard-allowed">ALLOWED</b>
              <button
                type="button"
                class="guard-revoke-btn"
                onclick="revokeGuardCommand(${JSON.stringify(command)})">
                REVOKE
              </button>
            </div>
          </div>
        `).join("");
      }
    }

  }catch(err){
    console.error("Command Guard error:", err);
  }
}

async function allowGuardCommand(command){
  if(!command) return;

  const confirmed = confirm(
    "Allow this exact command?\n\n" +
    command +
    "\n\nThis will be added to the SentinelSOC analyst allowlist."
  );

  if(!confirmed) return;

  try{
    const r = await fetch("/api/v2/command-guard/allow", {
      method:"POST",
      headers:{
        "Content-Type":"application/json",
        "Accept":"application/json"
      },
      body:JSON.stringify({command})
    });

    const text = await r.text();

    if(!r.ok){
      throw new Error("HTTP " + r.status + ": " + text);
    }

    await loadCommandGuard();
  }catch(err){
    console.error("Allow command failed:", err);
    alert("Unable to allow this command.");
  }
}

async function revokeGuardCommand(command){
  if(!command) return;

  const confirmed = confirm(
    "Revoke this command from the analyst allowlist?\n\n" +
    command +
    "\n\nFuture executions will be checked against the destructive policy again."
  );

  if(!confirmed) return;

  try{
    const r = await fetch("/api/v2/command-guard/allow", {
      method:"DELETE",
      headers:{
        "Content-Type":"application/json",
        "Accept":"application/json"
      },
      body:JSON.stringify({command})
    });

    const text = await r.text();

    if(!r.ok){
      throw new Error("HTTP " + r.status + ": " + text);
    }

    await loadCommandGuard();
  }catch(err){
    console.error("Revoke command failed:", err);
    alert("Unable to revoke this command.");
  }
}

window.loadCommandGuard = loadCommandGuard;
window.toggleCommandGuard = toggleCommandGuard;
window.allowGuardCommand = allowGuardCommand;
window.revokeGuardCommand = revokeGuardCommand;

document.addEventListener("DOMContentLoaded", () => {
  loadCommandGuard();
  setInterval(loadCommandGuard, 5000);
});
