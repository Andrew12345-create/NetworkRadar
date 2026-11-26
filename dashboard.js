const $=id=>document.getElementById(id);
const UNKNOWN_IDENTITY_CONFIDENCE_THRESHOLD=35;
// Startup diagnostics: make a failed dashboard script/API visible instead of leaving skeletons.
try{const c=$("connection");if(c){c.textContent="SCRIPT ACTIVE";c.className="pill warn";}}catch(_e){}
window.addEventListener("error",e=>{try{const c=$("connection");if(c){c.textContent="SCRIPT ERROR";c.className="pill bad";}const u=$("updated");if(u)u.textContent="Dashboard error: "+(e.message||"unknown script error");}catch(_x){}});
window.addEventListener("unhandledrejection",e=>{try{const u=$("updated");if(u)u.textContent="Dashboard request error: "+String(e.reason?.message||e.reason||"unknown");}catch(_x){}});
function esc(v){return String(v??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
async function getJSON(p,timeoutMs=10000){const ctl=new AbortController();const timer=setTimeout(()=>ctl.abort(),timeoutMs);try{const r=await fetch(p,{cache:"no-store",signal:ctl.signal});let data={};try{data=await r.json();}catch(_){}if(!r.ok)throw new Error(data.error||("HTTP "+r.status));return data;}catch(error){if(ctl.signal.aborted){const timeout=new Error("Timed out after "+Math.ceil(timeoutMs/1000)+" seconds requesting "+p+". The local API may be busy; the request was cancelled safely.");timeout.code="NR_REQUEST_TIMEOUT";throw timeout;}throw error;}finally{clearTimeout(timer);}}
function pill(el,text,state){el.textContent=text;el.className="pill"+(state==="bad"?" bad":state==="warn"?" warn":"");}
function toast(m){const t=$("toast");t.textContent=m;t.style.display="block";setTimeout(()=>t.style.display="none",3500);}
let deviceCache=[];
function filterDevices(){
 const q=($("deviceSearch")?.value||"").toLowerCase().trim();
 const st=$("deviceFilter")?.value||"ALL";
 const rows=deviceCache.filter(x=>{
  const b=[x.ip,x.device_name,x.manual_name,x.device_type,x.manufacturer,x.mac,x.hostname,x.model,x.os_guess,x.open_ports,x.service_summary].join(" ").toLowerCase();
  const confidence=Number(x.identification_confidence||0);
  const unknown=confidence<UNKNOWN_IDENTITY_CONFIDENCE_THRESHOLD||/unclass|unidentified|unknown/i.test(String(x.device_type||""));
  const ok=st==="ALL"||(st==="ONLINE"&&x.status==="ONLINE")||(st==="OFFLINE"&&x.status==="OFFLINE")||(st==="TRUSTED"&&x.trust_state==="TRUSTED")||(st==="UNKNOWN"&&unknown)||(st==="HIGH_CONFIDENCE"&&confidence>=80);
  return ok&&(!q||b.includes(q));
 });
 $("deviceRows").innerHTML=rows.map(x=>`<tr class="clickrow" data-open-device="${esc(x.ip)}" tabindex="0" role="button"><td class="mono">${esc(x.ip)}</td><td>${esc(x.manual_name||x.device_name)}</td><td>${esc(x.device_type)}</td><td>${esc(x.model||"—")}</td><td>${esc(x.manufacturer)}</td><td>${esc(x.identification_confidence)}%</td><td class="risk-${esc(x.risk_band||"UNKNOWN")}">${esc(x.risk_band||"UNKNOWN")}</td><td class="${x.status==="ONLINE"?"green":"muted"}">${esc(x.status)}</td></tr>`).join("")||'<tr><td colspan="8">No matches.</td></tr>';
 $("deviceRows").querySelectorAll("[data-open-device]").forEach(row=>{
  row.addEventListener("click",()=>openDevice(row.dataset.openDevice));
  row.addEventListener("keydown",e=>{if(e.key==="Enter"||e.key===" "){e.preventDefault();openDevice(row.dataset.openDevice);}});
 });
}
function closeDevice(){$("deviceModal").classList.remove("open");}
function deviceRows(rows, cols, empty="No records available."){
 if(!rows||!rows.length)return `<div class="device-empty">${esc(empty)}</div>`;
 return `<div class="scroll"><table class="device-table"><thead><tr>${cols.map(c=>`<th>${esc(c[0])}</th>`).join("")}</tr></thead><tbody>${rows.map(r=>`<tr>${cols.map(c=>`<td>${esc((r[c[1]]??"—")=== "" ? "—" : (r[c[1]]??"—"))}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
}
function deviceProfileCards(items){return '<div class="profilegrid">'+items.map(([k,v])=>`<div class="profileitem"><div class="label">${esc(k)}</div><div class="value">${esc(v===0?"0":(v||"Unknown"))}</div></div>`).join("")+'</div>';}
function setDeviceTab(name){
 document.querySelectorAll("[data-device-tab]").forEach(b=>b.setAttribute("aria-selected",b.dataset.deviceTab===name?"true":"false"));
 document.querySelectorAll("[data-device-pane]").forEach(p=>p.classList.toggle("active",p.dataset.devicePane===name));
}
async function openDevice(ip){
 $("deviceModal").classList.add("open");$("modalTitle").textContent="Device Intelligence · "+ip;$("modalContent").textContent="Loading device intelligence...";
 try{
  const p=await getJSON("/api/device?ip="+encodeURIComponent(ip));const d=p.device;
  if(!d){$("modalContent").textContent="Device not found.";return;}
  const rec=d.recognition||{}, ev=p.identity_evidence||[], ass=p.identity_assessments||[];
  const tabs=["Overview","Identity","Hardware","Operating System","Network","Services","Behaviour","Relationships","Security","History","Investigations"];
  let html='<div class="device-tabs" role="tablist" aria-label="Device intelligence sections">'+tabs.map((t,i)=>`<button class="device-tab" role="tab" id="devtab-${i}" aria-controls="devpane-${i}" aria-selected="${i===0?"true":"false"}" data-device-tab="${esc(t)}">${esc(t)}</button>`).join("")+'</div>';
  const pane=(name,body,i)=>`<section class="device-pane ${i===0?"active":""}" role="tabpanel" id="devpane-${i}" aria-labelledby="devtab-${i}" data-device-pane="${esc(name)}">${body}</section>`;
  const overview=deviceProfileCards([["IP ADDRESS",d.ip],["DEVICE NAME",d.manual_name||d.device_name||d.hostname],["CATEGORY",d.device_type],["REPORTED MANUFACTURER",d.reported_manufacturer||"Not reported"],["MODEL",d.model],["OPERATING SYSTEM",d.os_guess],["MAC ADDRESS",d.mac],["IDENTITY CONFIDENCE",(d.identification_confidence||0)+"%"],["STATUS",d.status],["RISK",(d.risk_band||"UNKNOWN")+" · "+(d.risk_score||0)],["TRUST",d.trust_state],["FIRST SEEN",d.first_seen],["LAST SEEN",d.last_seen],["IDENTITY BASIS",d.identity_basis],["LAST ASSESSED",d.identity_last_assessed]]);
  let identity='<div class="device-kpis"><div class="device-kpi"><span class="label">Evidence records</span><strong>'+ev.length+'</strong></div><div class="device-kpi"><span class="label">Independent assessments</span><strong>'+ass.length+'</strong></div><div class="device-kpi"><span class="label">Category confidence</span><strong>'+(d.identity_category_confidence||0)+'%</strong></div></div>';
  const iq=rec.intelligence_quality||{};
  const iqDomains=Array.isArray(iq.domains)?iq.domains:[];
  identity+='<section class="identity-quality"><div class="identity-quality-head"><div><span class="label">IDENTITY INTELLIGENCE QUALITY</span><h3>Evidence coverage</h3><p>Completeness of collected information — not the probability that the device identity is correct.</p></div><div class="quality-score"><strong>'+esc(iq.coverage_score??0)+'%</strong><span>coverage</span></div></div>';
  identity+='<div class="quality-grid">'+iqDomains.map(x=>'<div class="quality-item"><div class="quality-item-head"><span>'+esc(x.label)+'</span><b>'+esc(x.score)+'%</b></div><div class="quality-track"><span style="width:'+Math.max(0,Math.min(100,Number(x.score)||0))+'%"></span></div><small>'+esc(x.observed)+' of '+esc(x.total)+' signals observed</small></div>').join('')+'</div>';
  identity+='<div class="quality-meta"><span>'+esc(iq.evidence_count??ev.length)+' evidence records</span><span>'+esc(iq.independent_families??0)+' source families</span><span>'+esc((iq.source_families||[]).join(' · ')||'No source families yet')+'</span></div>';
  if(iq.limitations?.length)identity+='<div class="hint quality-limit">'+iq.limitations.map(esc).join(' ')+'</div>';
  identity+='</section>';
  const reconciliation=rec.reconciliation||d.identity_reconciliation||{};
  if(reconciliation.accepted){
   identity+='<section class="identity-quality"><div class="identity-quality-head"><div><span class="label">IDENTITY RECONCILIATION · 14.2</span><h3>Current assessment vs accepted identity</h3><p>The latest scan is not automatically allowed to replace a stronger retained classification.</p></div><div class="quality-score"><strong>'+esc(reconciliation.action||"UNKNOWN")+'</strong><span>decision</span></div></div>';
   identity+=deviceProfileCards([["CURRENT ASSESSMENT",reconciliation.current?.device_type||"Unknown"],["CURRENT CONFIDENCE",(reconciliation.current?.confidence??0)+"%"],["ACCEPTED INVENTORY",reconciliation.accepted?.device_type||d.device_type||"Unknown"],["ACCEPTED CONFIDENCE",(reconciliation.accepted?.confidence??d.identification_confidence??0)+"%"],["PREVIOUS IDENTITY",reconciliation.previous?.device_type||"None"],["REPLACEMENT MARGIN",reconciliation.replacement_margin??8]]);
   identity+='<div class="notice">'+esc(reconciliation.explanation||"No reconciliation explanation available.")+'</div></section>';
  }
  const evidenceIntel=rec.evidence_intelligence||{};
  const evidenceAttributes=evidenceIntel.attributes||{};
  const evidenceRows=Object.keys(evidenceAttributes).map(k=>({attribute:k,value:evidenceAttributes[k].value,confidence:evidenceAttributes[k].confidence,independent_sources:evidenceAttributes[k].independent_sources,sources:(evidenceAttributes[k].sources||[]).join(" · "),conflict:evidenceAttributes[k].conflict?"CONFLICT":"—"}));
  if(evidenceRows.length){
   identity+='<h3>FRESHNESS-AWARE EVIDENCE INTELLIGENCE</h3><div class="hint">Repeated observations from one protocol family are capped. Old or undated evidence does not receive a fresh score; competing values remain visible.</div>';
   identity+=deviceRows(evidenceRows,[["ATTRIBUTE","attribute"],["VALUE","value"],["SCORE","confidence"],["INDEPENDENT FAMILIES","independent_sources"],["SOURCES","sources"],["CONFLICT","conflict"]]);
   identity+='<div class="hint">Historical evidence considered: '+esc(evidenceIntel.evidence_count??0)+' · ignored placeholders: '+esc(evidenceIntel.ignored_count??0)+'</div>';
  }
  identity+='<h3>WHY NETWORKRADAR THINKS THIS IS THIS DEVICE</h3>';
  identity+=deviceRows(ass,[['ATTRIBUTE','attribute'],['ASSESSED VALUE','value'],['CONFIDENCE','confidence'],['STATUS','status'],['EVIDENCE COUNT','evidence_count'],['INDEPENDENT SOURCES','independent_sources'],['RATIONALE','rationale']],'No persisted attribute assessments yet.');
  identity+='<h3>RAW IDENTITY EVIDENCE</h3>'+deviceRows(ev,[['TIME','timestamp'],['SOURCE','source'],['ATTRIBUTE','attribute'],['OBSERVED VALUE','value'],['CONFIDENCE','confidence'],['CLASS','class']]);
  if(rec.category){identity+=`<div class="notice"><b>${esc(rec.category)}</b> · ${esc(rec.confidence||0)}% · ${esc(rec.status||'UNKNOWN')}</div>`;identity+=deviceRows(rec.matches||[],[['MATCH','matched'],['CLASSIFICATION','category'],['SOURCE FAMILY','source_family'],['WEIGHT','weight']],'No signature matches.');}
  const osProfile=rec.operating_system||{};
  identity+='<section class="identity-quality"><div class="identity-quality-head"><div><span class="label">NETWORKRADAR IDENTITY ENGINE 14.2</span><h3>Evidence-fused device profile</h3><p>Independent protocol families are scored separately. Repeated observations from one family cannot manufacture extra confidence.</p></div><div class="quality-score"><strong>'+esc(rec.confidence??0)+'</strong><span>evidence score</span></div></div>';
  identity+=deviceProfileCards([["SELECTED CATEGORY",rec.selected_category||rec.category||"Unclassified"],["PROFILE STATUS",rec.status||"UNKNOWN"],["INDEPENDENT SOURCE FAMILIES",(rec.source_families||[]).length],["OS FAMILY",osProfile.family||"Not resolved"],["REPORTED MODEL",rec.model||"Not reported"],["REPORTED MANUFACTURER",rec.manufacturer||"Not reported"],["TCP PORTS",(rec.tcp_ports||[]).join(", ")||"Not observed"],["UDP PORTS",(rec.udp_ports||[]).join(", ")||"Not observed"],["NMAP SAFE SCRIPTS",(rec.nmap_scripts||[]).join(", ")||"Not collected"]]);
  identity+='<div class="quality-meta"><span>Evidence families: '+esc((rec.source_families||[]).join(" · ")||"None")+'</span></div>';
  if(osProfile.candidates?.length)identity+='<h3>OPERATING SYSTEM EVIDENCE</h3>'+deviceRows(osProfile.candidates,[["SOURCE","source"],["OBSERVED OS","value"],["RELIABILITY","reliability"]]);
  if(rec.ranked_categories?.length)identity+='<h3>RANKED DEVICE HYPOTHESES</h3>'+deviceRows(rec.ranked_categories,[["CANDIDATE","category"],["SCORE","confidence"],["INDEPENDENT FAMILIES","source_families"]]);
  if(rec.port_clues?.length)identity+='<div class="notice">Low-weight port context only: '+esc(rec.port_clues.join(" · "))+'. Ports alone do not establish a device type.</div>';
  if(rec.conflicting_classifications)identity+='<div class="notice">Competing device-family hypotheses detected. NetworkRadar has withheld a definitive category.</div>';
  if(rec.collection_notes?.length)identity+='<div class="notice">COLLECTION NOTES: '+esc(rec.collection_notes.join(' · '))+'</div>';
  identity+='</section>';
  const oui=rec.nic_address_block_registrant||{};
   let hardware=deviceProfileCards([["DEVICE-REPORTED MANUFACTURER",d.reported_manufacturer||"Not observed"],["IEEE ADDRESS-BLOCK REGISTRANT",oui.organization||d.oui_manufacturer||"Not found"],["IEEE REGISTRY",oui.registry||"Unknown"],["ASSIGNED PREFIX",oui.prefix||"—"],["PREFIX LENGTH",oui.prefix_bits?oui.prefix_bits+" bits":"—"],["REGISTRY RECORD UPDATED",oui.updated_at||"Unknown"],["NMAP MAC VENDOR",d.manufacturer],["REPORTED MODEL",d.model],["HOSTNAME",d.hostname],["DEVICE CATEGORY",d.device_type],["MAC ADDRESS",d.mac],["MAC IDENTITY BASIS",d.identity_basis]]);
   if(oui.interpretation) hardware+='<div class="notice">'+esc(oui.interpretation)+'. The registrant may be an adapter supplier, OEM, ODM or another assignee; it is not automatically the device maker.</div>';
   const endpointAgent=p.endpoint_agent||{}, endpointInv=endpointAgent.inventory||{};
   if(endpointAgent.agent_id){
    const endpointOs=endpointInv.operating_system||{}, endpointBios=endpointInv.bios||{};
    const cpuRows=Array.isArray(endpointInv.cpu)?endpointInv.cpu:[];
    const diskRows=Array.isArray(endpointInv.disks)?endpointInv.disks:[];
    const adapterRows=Array.isArray(endpointInv.network_adapters)?endpointInv.network_adapters:[];
    const memoryGiB=Number(endpointInv.total_memory_bytes||0)/1073741824;
    hardware+='<section class="identity-quality"><div class="identity-quality-head"><div><span class="label">AUTHENTICATED ENDPOINT INVENTORY</span><h3>Device-reported hardware profile</h3><p>Collected by an explicitly enrolled NetworkRadar endpoint agent. This is stronger hardware evidence than network fingerprints, but remains a device-reported inventory snapshot.</p></div><div class="quality-score"><strong>ENROLLED</strong><span>'+esc(endpointAgent.status||"UNKNOWN")+'</span></div></div>';
    hardware+=deviceProfileCards([["ENDPOINT MANUFACTURER",endpointInv.manufacturer||"Not reported"],["EXACT SYSTEM MODEL",endpointInv.model||"Not reported"],["SYSTEM FAMILY",endpointInv.system_family||"Not reported"],["BIOS VENDOR",endpointBios.vendor||"Not reported"],["BIOS VERSION",endpointBios.version||"Not reported"],["SERIAL NUMBER",endpointBios.serial_number||"Not collected"],["CPU",cpuRows.map(x=>x.name||"").filter(Boolean).join(" · ")||"Not reported"],["PHYSICAL MEMORY",memoryGiB>0?memoryGiB.toFixed(1)+" GiB":"Not reported"],["OPERATING SYSTEM",endpointOs.caption||"Not reported"],["OS VERSION / BUILD",[endpointOs.version,endpointOs.build].filter(Boolean).join(" / ")||"Not reported"],["ARCHITECTURE",endpointOs.architecture||"Not reported"],["AGENT LAST REPORT",endpointAgent.last_seen||"Unknown"],["AGENT ASSOCIATION",endpointAgent.association_basis||"Unknown"]]);
    hardware+='<div class="hint">Serial numbers are collected only when the endpoint is enrolled/run with the explicit --include-serial option. NetworkRadar does not infer a serial number from a MAC address or hostname.</div>';
    hardware+='<h3>PHYSICAL DISKS</h3>'+deviceRows(diskRows,[["MODEL","model"],["MANUFACTURER","manufacturer"],["SIZE (BYTES)","size_bytes"],["INTERFACE","interface_type"],["MEDIA","media_type"],["SERIAL","serial_number"]],"No disk inventory reported.");
    hardware+='<h3>ENDPOINT NETWORK ADAPTERS</h3>'+deviceRows(adapterRows,[["NAME","name"],["DESCRIPTION","description"],["MAC","mac"],["STATUS","status"],["LINK SPEED","link_speed"],["IPv4","ipv4"],["IPv6","ipv6"]],"No adapter inventory reported.");
    hardware+='</section>';
   }else{
    hardware+='<div class="notice">No authenticated endpoint inventory is linked to this device. Network-based identification remains available; exact hardware model and serial data require an explicitly enrolled endpoint agent.</div>';
   }
  const os=deviceProfileCards([["OS GUESS",d.os_guess],["OS FINGERPRINT CONFIDENCE",d.identification_confidence+"%"],["PASSIVE TCP HINT",rec.passive_tcp_os_hint],["RECOGNITION STATUS",rec.status],["ALTERNATIVE CLASSIFICATIONS",(rec.alternatives||[]).map(x=>x.category+" ("+x.confidence+"%)").join(" · ")],["LIMITATIONS",(rec.limitations||[]).join(" ")]]);
  const network=deviceProfileCards([["CURRENT IP",d.ip],["CURRENT MAC",d.mac],["IDENTITY KEY",d.device_id],["IDENTITY BASIS",d.identity_basis],["DHCP OBSERVATIONS",(p.dhcp_history||[]).length],["DNS OBSERVATIONS",(p.dns_activity||[]).length]]);
  let networkHtml=network+'<h3>DHCP HISTORY</h3>'+deviceRows(p.dhcp_history,[['TIME','timestamp'],['MESSAGE','message'],['HOSTNAME','hostname'],['VENDOR CLASS','vendor_class'],['PXE ARCHITECTURE','client_architecture'],['USER CLASS','user_class'],['CLIENT FQDN','client_fqdn'],['CLIENT MAC','mac'],['SERVER','server_ip']]);
  networkHtml+='<h3>IP / MAC HISTORY</h3>'+deviceRows(p.ip_history,[['IP','ip'],['MAC','mac'],['FIRST SEEN','first_seen'],['LAST SEEN','last_seen']]);
  const services=deviceProfileCards([["OPEN PORTS",d.open_ports],["SERVICE SUMMARY",d.service_summary],["SERVICE SIGNATURES",(rec.matches||[]).filter(x=>String(x.source_family||"").toLowerCase().includes("service")).length],["TLS CERTIFICATES",(rec.evidence||[]).filter(x=>String(x.source||"").toLowerCase().includes("tls")).length],["SNMP DATA",Object.keys(d.snmp_intel||{}).length?"Available":"Not observed"]]);
  let serviceHtml=services+'<h3>IDENTIFIED SERVICE EVIDENCE</h3>'+deviceRows((rec.evidence||[]).filter(x=>/service|tls|snmp|http|ssh|smb/i.test((x.source||"")+" "+(x.family||""))),[['SOURCE','source'],['FAMILY','family'],['OBSERVATION','value']]);
  serviceHtml+='<h3>PORT SCAN HISTORY</h3>'+deviceRows(p.port_scan_history,[['TIME','timestamp'],['COMPLETED','completed'],['PORTS','ports'],['METHOD','method'],['DETAIL','detail']]);
  const behaviour='<h3>DNS ACTIVITY (LATEST OBSERVATIONS)</h3>'+deviceRows(p.dns_activity,[['TIME','timestamp'],['DOMAIN','domain'],['TYPE','type'],['RESPONSE','rcode'],['ANSWERS','answers']]);
  const behaviour2='<h3>BEHAVIOUR ALERTS</h3>'+deviceRows(p.behaviour_alerts,[['TIME','timestamp'],['METRIC','metric'],['OBSERVED','observed'],['BASELINE','baseline'],['SEVERITY','severity'],['STATUS','status'],['DETAILS','details']]);
  const relations='<h3>DEVICE RELATIONSHIPS</h3>'+deviceRows(p.relationships,[['SOURCE IP','source_ip'],['TARGET IP','target_ip'],['TYPE','type'],['CONFIDENCE','confidence'],['EVIDENCE','evidence'],['LAST SEEN','last_seen']]);
  const relations2='<h3>TOPOLOGY LINKS</h3>'+deviceRows(p.topology,[['SOURCE','source'],['TARGET','target'],['KIND','kind'],['CONFIDENCE','confidence'],['EVIDENCE','evidence'],['LAST SEEN','last_seen']]);
  let security=deviceProfileCards([["RISK SCORE",d.risk_score||0],["RISK BAND",d.risk_band||"UNKNOWN"],["THREAT RISK",d.threat_risk||0],["IDENTITY UNCERTAINTY",d.identification_uncertainty||0],["OPERATIONAL HEALTH",d.operational_health||0],["TRUST STATE",d.trust_state]]);
  security+='<h3>EXPOSURE FINDINGS</h3>'+deviceRows(p.exposure_findings,[['TITLE','title'],['SEVERITY','severity'],['CONFIDENCE','confidence'],['PORTS','ports'],['STATUS','status'],['RECOMMENDATION','recommendation']]);
  security+='<h3>SECURITY ALERTS</h3>'+deviceRows(p.alerts,[['TIME','timestamp'],['SOURCE','source'],['RULE','rule'],['SEVERITY','severity'],['TITLE','title'],['STATUS','status']]);
  if(d.risk_explanation)security+='<div class="notice">'+esc(d.risk_explanation)+'</div>';
  const history='<h3>IDENTITY CHANGES</h3>'+deviceRows(p.identity_history,[['TIME','timestamp'],['ATTRIBUTE','attribute'],['OLD VALUE','old'],['NEW VALUE','new'],['REASON','reason']]);
  const history2='<h3>DISCOVERY OBSERVATIONS</h3>'+deviceRows(p.observations,[['TIME','timestamp'],['METHOD','method'],['OBSERVATION','observation'],['CONFIDENCE','confidence']]);
  const investigations=deviceRows(p.investigations,[['ID','id'],['CREATED','timestamp'],['TITLE','title'],['SEVERITY','severity'],['CONFIDENCE','confidence'],['STATUS','status'],['DESCRIPTION','description'],['CLOSURE','closure_reason']]);
  html+=pane("Overview",overview,0)+pane("Identity",identity,1)+pane("Hardware",hardware,2)+pane("Operating System",os,3)+pane("Network",networkHtml,4)+pane("Services",serviceHtml,5)+pane("Behaviour",behaviour+behaviour2,6)+pane("Relationships",relations+relations2,7)+pane("Security",security,8)+pane("History",history+history2,9)+pane("Investigations",investigations,10);
  $("modalContent").innerHTML=html;
  $("modalContent").querySelectorAll("[data-device-tab]").forEach(b=>b.addEventListener("click",()=>setDeviceTab(b.dataset.deviceTab)));
 }catch(err){$("modalContent").textContent="Error loading device intelligence: "+err.message;}
}
async function runContinuity(){
 const b=$("continuityRun");b.disabled=true;b.textContent="ANALYSING...";
 try{
  const r=await fetch("/api/identity/continuity/run",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({confirm:true})});
  const p=await r.json();if(!r.ok)throw new Error(p.error||"Analysis failed");
  toast(`PHANTOM TRACK: ${p.result.observed} observations · ${p.result.stable_anchors} stable anchors · ${p.result.randomised} randomised · ${p.result.candidate_groups} review groups.`);
  await loadContinuity();await loadCandidates();
 }catch(e){toast("Continuity: "+e.message);}finally{b.disabled=false;b.textContent="RUN CONTINUITY ANALYSIS";}
}
async function updateOUI(){
 if(!confirm("Download and cache the official IEEE MAC address registries? Requires internet."))return;
 try{
  const r=await fetch("/api/intelligence/update-oui",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({confirm:true})});
  const p=await r.json();if(!r.ok)throw new Error((p.errors||[]).join("; ")||p.error||"Update failed");
  toast(`IEEE registry: ${p.updated} prefixes.`);await loadIdentityIntel();
 }catch(e){toast("OUI update: "+e.message);}
}
async function authorizeCurrentNetwork(){
 if(!confirm("Only authorise if you own this network."))return;
 try{
  const r=await fetch("/api/network/authorize",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({confirm:true})});
  const j=await r.json();if(!r.ok)throw new Error(j.error||"Failed");
  toast(j.message);await refreshAll();
 }catch(e){toast(e.message);}
}
async function scanNow(){
 const b=$("scanButton");b.disabled=true;b.textContent="QUEUED...";
 try{const r=await fetch("/api/scan",{method:"POST"});let payload={};try{payload=await r.json();}catch(_){}if(!r.ok)throw new Error(payload.error||("HTTP "+r.status));$("updated").textContent="Scan request accepted. Waiting for discovery worker...";toast("Scan queued. Live progress is shown in the navigation bar.");}
 catch(e){$("updated").textContent="Scan request failed: "+e.message;toast("Could not queue scan: "+e.message);}
 finally{setTimeout(()=>{b.disabled=false;b.textContent="SCAN NOW";},2500);}
}
async function loadCandidates(){
 try{
  const c=await getJSON("/api/identity/candidates?status=PENDING");
  $("candidateRows").innerHTML=c.map(x=>`<tr><td>${x.id}</td><td class="mono">${esc(x.device_a)}</td><td class="mono">${esc(x.device_b)}</td><td>${esc(x.outcome)}</td><td>${(x.score*100).toFixed(1)}%</td><td>${esc(x.status)}</td><td><button class="secondary" style="padding:3px 8px;font-size:10px" onclick="reviewCandidate(${x.id},'ACCEPT')">ACCEPT</button> <button class="secondary" style="padding:3px 8px;font-size:10px" onclick="reviewCandidate(${x.id},'REJECT')">REJECT</button></td></tr>`).join("")||'<tr><td colspan="7">No pending candidates.</td></tr>';
 }catch(e){$("candidateRows").innerHTML='<tr><td colspan="7">Error: '+esc(e.message)+'</td></tr>';}
}
async function reviewCandidate(id,action){
 try{
  const r=await fetch("/api/identity/candidates/review",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({id,action,reviewer:"local-user"})});
  const p=await r.json();if(!r.ok)throw new Error(p.error||"Failed");
  toast("Candidate #"+id+" "+action.toLowerCase()+"d.");await loadCandidates();
 }catch(e){toast(e.message);}
}
async function loadContinuity(){
 try{
  const [s,d]=await Promise.all([getJSON('/api/identity/continuity/summary'),getJSON('/api/identity/continuity/devices')]);
  $('ctTracked').textContent=s.tracked||0;$('ctStable').textContent=s.stable_anchors||0;$('ctRandom').textContent=s.randomised_observations||0;$('ctEvents').textContent=s.events||0;
  $('continuityRows').innerHTML=d.map(x=>`<tr><td class="mono">${esc(x.id)}</td><td class="mono">${esc(x.ip)}</td><td>${esc(x.anchor_type)}</td><td>${esc(x.hostname||'—')}</td><td>${esc(x.vendor_class||'—')}</td><td>${esc(x.confidence)}%</td><td>${esc(x.observations)}</td><td>${esc(x.last_seen)}</td></tr>`).join('')||'<tr><td colspan="8">No identity observations yet.</td></tr>';
 }catch(e){$('continuityRows').innerHTML='<tr><td colspan="8">Continuity service unavailable: '+esc(e.message)+'</td></tr>';}
}
async function loadIdentityIntel(){
 try{
  const [s,u]=await Promise.all([getJSON("/api/identity/summary"),getJSON("/api/identity/unknown")]);
  $("idDevices").textContent=s.devices_with_evidence||0;$("idEvidence").textContent=s.evidence_records||0;$("ouiEntries").textContent=s.oui_entries||0;$("idLastRun").textContent=s.last_run?s.last_run.timestamp:"Not run";
 }catch(e){$("idLastRun").textContent="Unavailable";}
}
async function loadProfiles(){
 try{
  const p=await getJSON("/api/profiles");
  $("profileRows").innerHTML=p.map(x=>`<tr style="${x.is_current?'background:#173653':''}"><td class="mono">${esc(x.network)}${x.is_current?' <span class="pill">CUR</span>':''}</td><td class="mono">${esc(x.fingerprint)}</td><td class="mono">${esc(x.gateway)}</td><td>${x.approved?'<span class="green">YES</span>':'<span class="amber">NO</span>'}</td><td>${esc(x.confidence)}%</td><td>${esc(x.last_seen)}</td></tr>`).join("")||'<tr><td colspan="6">None.</td></tr>';
 }catch(e){}
}
async function loadChanges(){
 try{const c=await getJSON("/api/changes");$("changeRows").innerHTML=c.map(x=>`<tr><td>${esc(x.timestamp)}</td><td>${esc(x.change_type)}</td><td>${esc(x.category)}</td><td class="${x.severity==="HIGH"?"red":x.severity==="MEDIUM"?"amber":"muted"}">${esc(x.severity)}</td><td class="mono">${esc(x.ip)}</td><td>${esc(x.details)}</td></tr>`).join("")||'<tr><td colspan="6">None.</td></tr>';}catch(e){}
}
async function loadConfig(){
 try{const c=await getJSON("/api/config_findings");$("configRows").innerHTML=c.map(x=>`<tr><td class="${x.severity==="HIGH"?"red":x.severity==="MEDIUM"?"amber":"muted"}">${esc(x.severity)}</td><td>${esc(x.title)}<div class="muted">${esc(x.description)}</div></td><td style="font-size:11px">${esc(x.evidence)}</td><td style="font-size:11px">${esc(x.recommendation)}</td><td>${esc(x.status)}</td></tr>`).join("")||'<tr><td colspan="5">No findings.</td></tr>';}catch(e){}
}
async function loadAlertStream(){
 try{const a=await getJSON("/api/alerts_stream");$("alertStreamRows").innerHTML=a.map(x=>`<tr><td>${esc(x.timestamp)}</td><td>${esc(x.source)}</td><td>${esc(x.rule_id)}</td><td class="${x.severity==="HIGH"?"red":x.severity==="MEDIUM"?"amber":"muted"}">${esc(x.severity)}</td><td>${esc(x.title)}</td><td>${esc(x.occurrence_count||1)}</td><td>${x.investigation_id?'#'+x.investigation_id:'—'}</td></tr>`).join("")||'<tr><td colspan="7">None.</td></tr>';}catch(e){}
}
async function loadHuntTemplates(){
 try{const t=await getJSON("/api/hunt/templates");$("huntTemplate").innerHTML='<option value="">Select...</option>'+t.map(x=>`<option value="${esc(x.key)}">${esc(x.title)}</option>`).join("");}catch(e){}
}
async function runHunt(){
 const tpl=$("huntTemplate").value;if(!tpl){toast("Select template.");return;}
 $("huntResult").textContent="Running...";
 try{const r=await getJSON("/api/hunt/run?template="+encodeURIComponent(tpl));
  if(r.error){$("huntResult").textContent="Error: "+r.error;return;}
  $("huntResult").textContent=`${r.title} — ${r.count} results`;
  $("huntHead").innerHTML='<tr>'+r.columns.map(c=>`<th>${esc(c)}</th>`).join("")+'</tr>';
  $("huntRows").innerHTML=r.results.map(row=>'<tr>'+r.columns.map(c=>`<td class="mono">${esc(row[c]??"")}</td>`).join("")+'</tr>').join("")||'<tr><td colspan="'+r.columns.length+'">No results.</td></tr>';
 }catch(e){$("huntResult").textContent="Error: "+e.message;}
}
async function downloadReport(){
 const t=$("reportType").value;const f=$("reportFormat").value;
 window.location.href=`/api/report?type=${encodeURIComponent(t)}&format=${encodeURIComponent(f)}`;
}
let networkWorkspaceCache=[];
let selectedWorkspaceId="";
let lastActiveWorkspaceId="";
let workspaceLoadToken=0;

async function selectNetworkWorkspace(networkId){
 selectedWorkspaceId=networkId||"";
 await renderNetworkWorkspace(selectedWorkspaceId);
}
async function loadNetworkWorkspaces(){
 try{
  const rows=await getJSON("/api/networks/workspaces");
  networkWorkspaceCache=Array.isArray(rows)?rows:[];
  const current=networkWorkspaceCache.find(x=>x.is_current);
  const currentId=current?.network_id||"";
  if(currentId&&currentId!==lastActiveWorkspaceId){
   selectedWorkspaceId=currentId;
   lastActiveWorkspaceId=currentId;
  }
  if(!selectedWorkspaceId||!networkWorkspaceCache.some(x=>x.network_id===selectedWorkspaceId)){
   selectedWorkspaceId=currentId||networkWorkspaceCache[0]?.network_id||"";
  }
  const picker=$("workspaceSelect");
  if(picker){
   picker.innerHTML=networkWorkspaceCache.map(w=>'<option value="'+esc(w.network_id)+'">'+esc(w.display_name)+' · '+esc(w.network_type)+' · '+esc(w.subnet||"No subnet")+(w.is_current?" · ACTIVE":"")+(w.approved?" · APPROVED":" · NOT APPROVED")+'</option>').join("")||'<option value="">No workspaces observed yet</option>';
   picker.value=selectedWorkspaceId;
  }
  await renderNetworkWorkspace(selectedWorkspaceId);
 }catch(e){
  const notice=$("workspaceNotice");
  if(notice)notice.textContent="Network workspace directory unavailable: "+e.message;
 }
}
async function renderNetworkWorkspace(networkId){
 const token=++workspaceLoadToken;
 const w=networkWorkspaceCache.find(x=>x.network_id===networkId);
 const set=(id,value)=>{const el=$(id);if(el)el.textContent=value||"—";};
 if(!w){
  set("workspaceName","No network workspace");
  set("workspaceType","—");set("workspaceSubnet","—");set("workspaceLastSeen","—");set("workspaceAuthorization","—");
  if($("workspaceInterfaceRows"))$("workspaceInterfaceRows").innerHTML='<tr><td colspan="6">No interface history yet.</td></tr>';
  if($("workspaceDeviceRows"))$("workspaceDeviceRows").innerHTML='<tr><td colspan="5">No device sightings yet.</td></tr>';
  return;
 }
 set("workspaceName",w.display_name);
 set("workspaceType",w.network_type);
 set("workspaceSubnet",w.subnet||"Unknown subnet");
 set("workspaceLastSeen",w.last_seen);
 set("workspaceAuthorization",w.approved?"APPROVED":"REAPPROVAL REQUIRED");
 const notice=$("workspaceNotice");
 if(notice)notice.textContent=(w.is_current?"ACTIVE WORKSPACE · ":"HISTORICAL WORKSPACE · ")+
  "This view is read-only. Active discovery and approval remain bound to the current primary network. "+
  (w.approved?"Workspace approval is current.":"This workspace is not approved for active discovery.")+" "+
  (w.fingerprint_count||0)+" fingerprint observation(s) · "+(w.device_count||0)+" device sighting(s).";
 try{
  const [interfaces,devices]=await Promise.all([
   getJSON("/api/networks/interfaces?network_id="+encodeURIComponent(networkId)),
   getJSON("/api/networks/devices?network_id="+encodeURIComponent(networkId))
  ]);
  if(token!==workspaceLoadToken)return;
  $("workspaceInterfaceRows").innerHTML=(interfaces||[]).map(x=>'<tr>'+
   '<td>'+esc(x.interface)+'<div class="muted small-note">'+esc(x.description||"")+'</div></td>'+
   '<td>'+esc(x.interface_type)+'</td>'+
   '<td class="mono">'+esc(x.ip||"—")+'<div class="muted small-note">'+esc(x.network||"")+'</div></td>'+
   '<td class="mono">'+esc(x.gateway||"—")+'</td>'+
   '<td>'+esc(x.ssid||"—")+'<div class="muted small-note mono">'+esc(x.bssid||"")+'</div></td>'+
   '<td>'+(x.is_primary?'<span class="pill ok">PRIMARY</span>':'<span class="pill">INTERFACE</span>')+'</td>'+
  '</tr>').join("")||'<tr><td colspan="6">No interface observations recorded for this workspace.</td></tr>';
  $("workspaceDeviceRows").innerHTML=(devices||[]).map(x=>'<tr>'+
   '<td class="mono">'+esc(x.ip)+'</td><td>'+esc(x.hostname||"—")+'</td>'+
   '<td class="mono">'+esc(x.mac||"—")+'</td><td>'+esc(x.status)+'</td><td>'+esc(x.last_seen)+'</td>'+
  '</tr>').join("")||'<tr><td colspan="5">No device sightings recorded yet. A completed inventory enrichment pass will populate this table.</td></tr>';
 }catch(e){
  if(token!==workspaceLoadToken)return;
  $("workspaceInterfaceRows").innerHTML='<tr><td colspan="6">Workspace data unavailable: '+esc(e.message)+'</td></tr>';
  $("workspaceDeviceRows").innerHTML='<tr><td colspan="5">Workspace data unavailable.</td></tr>';
 }
}

let refreshInFlight=false;
let forceRefreshQueued=false;
let firewallRefreshInFlight=false;
let firewallRefreshQueued=false;

/* NIGHTWATCH live presentation: all values come from existing local APIs. */
function nwSet(id,value){const el=$(id);if(el)el.textContent=value==null?"—":String(value);}
function nwPortCount(rows){const ports=new Set();(rows||[]).forEach(d=>String(d.open_ports||"").split(/[;,\s]+/).forEach(t=>{const m=t.trim().match(/^(\d{1,5})(?:\/(?:tcp|udp))?$/i);if(m)ports.add(m[1]);}));return ports.size;}
function nwTopology(data){
 const svg=$("nwTopology");if(!svg)return;
 const nodes=Array.isArray(data.nodes)?data.nodes.slice(0,40):[],edges=Array.isArray(data.edges)?data.edges.slice(0,100):[];
 const pos=new Map(),cx=500,cy=245,rx=390,ry=175;
 nodes.forEach((n,i)=>{const a=-Math.PI/2+2*Math.PI*i/Math.max(nodes.length,1);pos.set(String(n.id),{x:cx+Math.cos(a)*rx,y:cy+Math.sin(a)*ry});});
 let out='<circle cx="500" cy="245" r="92" class="nw-map-core"/><text x="500" y="241" text-anchor="middle" class="nw-core-label">NETWORK</text><text x="500" y="262" text-anchor="middle" class="nw-core-sub">OBSERVED ACTIVITY</text>',count=0;
 edges.forEach(e=>{const a=pos.get(String(e.source)),b=pos.get(String(e.target));if(!a||!b)return;const t=String(e.type||"").toUpperCase(),cl=t.includes("DHCP")?"dhcp":t.includes("MDNS")||t.includes("LLMNR")?"discovery":"dns";out+='<line x1="'+a.x+'" y1="'+a.y+'" x2="'+b.x+'" y2="'+b.y+'" class="nw-edge '+cl+'"/>';count++;});
 nodes.forEach(n=>{const p=pos.get(String(n.id));if(!p)return;const ip=String(n.id||""),label=String(n.label||ip).slice(0,22),kind=String(n.kind||"");const cl=/resolver|multicast|dhcp_server/.test(kind)?"resolver":kind==="observed"?"observed":"device";const clickable=/^(?:\d{1,3}\.){3}\d{1,3}$/.test(ip);out+='<g class="nw-node '+cl+'" '+(clickable?'data-nw-ip="'+esc(ip)+'" role="button" tabindex="0"':'')+'><circle cx="'+p.x+'" cy="'+p.y+'" r="13" class="nw-node-halo"/><circle cx="'+p.x+'" cy="'+p.y+'" r="6" class="nw-node-dot"/><text x="'+p.x+'" y="'+(p.y+27)+'" text-anchor="middle" class="nw-node-label">'+esc(label)+'</text></g>';});
 if(!nodes.length)out='<text x="500" y="230" text-anchor="middle" class="nw-svg-empty">NO NETWORK RELATIONSHIPS OBSERVED YET</text><text x="500" y="258" text-anchor="middle" class="nw-svg-sub">Run discovery and allow local observations to accumulate.</text>';
 svg.innerHTML=out;svg.querySelectorAll("[data-nw-ip]").forEach(el=>{const go=()=>openDevice(el.getAttribute("data-nw-ip"));el.addEventListener("click",go);el.addEventListener("keydown",e=>{if(e.key==="Enter"||e.key===" "){e.preventDefault();go();}});});
 nwSet("nwTopologyNote",nodes.length+" nodes · "+count+" observed relationships");nwSet("nwRadarCount",nodes.length+" SIGNALS");
}
function nwActivity(events,alerts){
 const el=$("nwActivityFeed");if(!el)return;const items=[];
 (events||[]).forEach(x=>items.push({time:x.timestamp,ip:x.ip,title:x.event_type||"Network event",detail:x.details||x.category||"Recorded observation",severity:x.severity||"INFO"}));
 (alerts||[]).forEach(x=>items.push({time:x.timestamp,ip:x.client_ip,title:x.rule_id||"Network alert",detail:x.details||x.domain||"Recorded alert",severity:x.severity||"INFO"}));
 items.sort((a,b)=>String(b.time||"").localeCompare(String(a.time||"")));
 const list=items.slice(0,12);el.innerHTML=list.length?list.map(x=>{const s=String(x.severity).toUpperCase(),cl=s==="HIGH"||s==="CRITICAL"?"high":s==="MEDIUM"?"medium":"info";return '<article class="nw-feed-item"><time>'+esc(x.time||"Time unavailable")+'</time><div><b>'+esc(x.title)+'</b><small>'+esc(x.detail)+'</small></div><span>'+esc(x.ip||"LOCAL")+'</span><em class="'+cl+'">'+esc(s)+'</em></article>';}).join(""):'<div class="nw-feed-empty">No recent events or alerts have been recorded. This does not mean the network is threat-free.</div>';
}
function renderFirewall(f){
 const badge=$("fwStatusBadge"),host=$("firewallSnapshot");
 if(!host)return;
 const status=String(f.status||"UNKNOWN").toUpperCase();
 if(badge){badge.textContent=status;badge.className=status==="ONLINE"?"fw-online":"fw-degraded";}
 const profiles=Array.isArray(f.profiles)?f.profiles:[];
 const counts=f.rule_counts||{};
 const cards=[["ENABLED PROFILES",profiles.filter(x=>x.enabled).length+" / "+profiles.length],["ACTIVE RULES",counts.enabled??"—"],["INBOUND RULES",counts.inbound??"—"],["OUTBOUND RULES",counts.outbound??"—"],["BLOCK RULES",counts.block??"—"],["ALLOW RULES",counts.allow??"—"]];
 const cacheNote=f.cached?" · cached "+(f.cache_age_seconds??0)+"s ago":"";
 host.innerHTML='<div class="fw-metrics">'+cards.map(([k,v])=>'<article><span>'+esc(k)+'</span><strong>'+esc(v)+'</strong></article>').join('')+'</div>'+
  '<div class="fw-profiles">'+(profiles.map(p=>'<article><b>'+esc(p.name)+'</b><span class="'+(p.enabled?'fw-on':'fw-off')+'">'+(p.enabled?'ENABLED':'DISABLED')+'</span><small>Inbound: '+esc(p.default_inbound_action)+' · Outbound: '+esc(p.default_outbound_action)+'</small></article>').join('')||'<div class="nw-feed-empty">No Windows firewall profiles returned.</div>')+'</div>'+
  '<p class="fw-message">'+esc((f.message||"Firewall status unavailable.")+cacheNote)+'</p>';
}
async function loadFirewallSnapshot(force=false){
 if(firewallRefreshInFlight){
  if(force)firewallRefreshQueued=true;
  return;
 }
 firewallRefreshInFlight=true;
 try{
  const snapshot=await getJSON(force?"/api/firewall?refresh=1":"/api/firewall",30000);
  renderFirewall(snapshot||{});
 }catch(err){
  renderFirewall({status:"DEGRADED",profiles:[],rule_counts:{},
   message:"Firewall refresh failed: "+String(err?.message||err||"request failed")});
 }finally{
  firewallRefreshInFlight=false;
  if(firewallRefreshQueued){
   firewallRefreshQueued=false;
   void loadFirewallSnapshot(true);
  }
 }
}
function renderNightwatch(s,n,d,dns,a,e,t){
 const statusOf=x=>String(x.status||"UNKNOWN").toUpperCase();
 const online=d.filter(x=>statusOf(x)==="ONLINE").length;
 const offline=d.filter(x=>statusOf(x)==="OFFLINE").length;
 const other=d.length-online-offline;
 const unknown=d.filter(x=>/unknown|unclassified|unidentified/i.test(String(x.device_type||""))||Number(x.identification_confidence||0)<UNKNOWN_IDENTITY_CONFIDENCE_THRESHOLD).length;
 nwSet("nwNetwork",n.network||s.network||"Network not identified");nwSet("nwGateway",n.gateway||"Not observed");nwSet("nwLastSync",new Date().toLocaleTimeString());
 nwSet("nwDevices",d.length);nwSet("nwOnline",online);nwSet("nwUnknown",unknown);nwSet("nwPorts",nwPortCount(d));nwSet("nwDns",dns.length);nwSet("nwAlerts",a.length);
 const statusNote=$("nwInventoryStatus");
 if(statusNote)statusNote.textContent=online+" ONLINE · "+offline+" OFFLINE · "+other+" OTHER / UNVERIFIED — totals reconcile to "+d.length+" known assets.";
 const nodes=Array.isArray(t?.nodes)?t.nodes:[];
 nwSet("nwRadarCount",nodes.length+" SIGNALS");
 nwSet("nwScanState",s.scan_status||s.discovery_status||"ENGINE ONLINE");nwSet("nwAuthState",n.authorized?"NETWORK AUTHORISED":"PASSIVE / NOT AUTHORISED");nwSet("nwEngineState","LOCAL API CONNECTED");
 const auth=$("nwAuthState");if(auth)auth.classList.toggle("authorised",!!n.authorized);nwTopology(t||{});nwActivity(e,a);
}

function renderResilience(payload){
 const current=payload?.current||{};
 const status=String(current.status||"STARTING").toUpperCase();
 const badge=$("resilienceStateBadge");
 if(badge){badge.textContent=status;badge.className="pill "+(status==="ONLINE"?"ok":status==="DEGRADED"?"warn":"bad");}
 const set=(id,value)=>{const el=$(id);if(el)el.textContent=value===undefined||value===null||value===""?"—":String(value);};
 set("resilienceScore",current.health_score===undefined||current.health_score===null?"—":current.health_score+"/100");
 set("resilienceLatency",current.avg_latency_ms===undefined||current.avg_latency_ms===null?"—":current.avg_latency_ms+" ms");
 set("resilienceLoss",current.packet_loss_percent===undefined||current.packet_loss_percent===null?"—":current.packet_loss_percent+"%");
 set("resilienceGateway",current.gateway_status||"—");
 set("resilienceGatewayLatency",current.gateway_avg_rtt_ms===undefined||current.gateway_avg_rtt_ms===null?"No ICMP reply":current.gateway_avg_rtt_ms+" ms average RTT");
 set("resilienceInternet",current.internet_tcp_reachable===true?"REACHABLE":current.internet_tcp_reachable===false?"UNREACHABLE":"—");
 set("resilienceTcpLatency",current.tcp_latency_ms===undefined||current.tcp_latency_ms===null?"TCP/443 check":"TCP connect "+current.tcp_latency_ms+" ms");
 set("resilienceDns",current.dns_status||"—");
 set("resilienceDnsLatency",current.dns_resolution_ms===undefined||current.dns_resolution_ms===null?"Resolver timing unavailable":current.dns_resolution_ms+" ms");
 set("resilienceLastSample",current.timestamp?("Last sample "+current.timestamp+" · "+(current.adapter||"adapter unknown")+" · "+(current.gateway||"gateway unknown")):(current.message||"Waiting for the first resilience sample."));
 const history=Array.isArray(payload?.history)?payload.history:[];
 const rows=$("resilienceHistoryRows");
 if(rows)rows.innerHTML=history.map(x=>'<tr><td>'+esc(x.timestamp||"—")+'</td><td>'+esc(x.status||"—")+'</td><td>'+esc(x.health_score??"—")+'</td><td>'+esc(x.avg_latency_ms===null||x.avg_latency_ms===undefined?"—":x.avg_latency_ms+" ms")+'</td><td>'+esc(x.packet_loss_percent===null||x.packet_loss_percent===undefined?"—":x.packet_loss_percent+"%")+'</td><td>'+esc(x.dns_status||"—")+'</td></tr>').join("")||'<tr><td colspan="6">Waiting for measurements…</td></tr>';
 const events=Array.isArray(payload?.events)?payload.events:[];
 const eventBox=$("resilienceEvents");
 if(eventBox)eventBox.innerHTML=events.map(x=>'<article class="nw-feed-item"><time>'+esc(x.timestamp||"—")+'</time><div><b>'+esc(x.event_type||"NETWORK EVENT")+'</b><small>'+esc(x.details||((x.previous_state||"")+" → "+(x.current_state||"")))+'</small></div><em class="'+(x.severity==="CRITICAL"||x.severity==="HIGH"?"high":x.severity==="MEDIUM"?"medium":"info")+'">'+esc(x.severity||"INFO")+'</em></article>').join("")||'<div class="nw-feed-empty">No resilience transitions recorded yet.</div>';
}
function renderScanMonitor(job){
 const state=String(job?.state||"IDLE").toUpperCase();
 const phase=String(job?.phase||"Waiting");
 const message=String(job?.message||"Waiting for the next discovery cycle.");
 const percent=Math.max(0,Math.min(100,Number(job?.percent)||0));
 const monitor=$("scanMonitor");
 if(monitor)monitor.dataset.state=state;
 const phaseEl=$("navScanPhase"),percentEl=$("navScanPercent"),bar=$("navScanBar"),detail=$("navScanDetail");
 if(phaseEl)phaseEl.textContent=state==="RUNNING"?phase.toUpperCase():state==="COMPLETED"?"COMPLETE":state==="ERROR"?"SCAN ERROR":state==="WAITING_AUTHORIZATION"?"AUTHORISE":state;
 if(percentEl)percentEl.textContent=percent+"%";
 if(bar)bar.style.width=percent+"%";
 if(detail){detail.textContent=message;detail.title=message;}
 const history=Array.isArray(job?.history)?job.history.slice(-5).reverse():[];
 const list=$("jobHistory");
 if(list&&history.length){
  list.innerHTML=history.map(item=>{const stamp=String(item.timestamp||"").split(" ").pop()||"—";return '<li><time>'+esc(stamp)+'</time><span><strong>'+esc(item.phase||item.state||"UPDATE")+'</strong> · '+esc(item.message||"")+'</span></li>';}).join("");
 }else if(list){list.innerHTML='<li>Waiting for scan activity.</li>';}
}

function renderIdentityTimeline(events){
 const rows=(Array.isArray(events)?events:[]).filter(item=>item.event_type==="DEVICE_IDENTITY_ASSESSED").slice(0,40);
 $("identityTimelineRows").innerHTML=rows.map(item=>'<tr><td>'+esc(item.timestamp||"—")+'</td><td class="mono">'+esc(item.ip||"—")+'</td><td>'+esc(item.details||"—")+'</td></tr>').join("")||'<tr><td colspan="3">No identity assessment events yet. Run a scan to populate this timeline.</td></tr>';
}

function renderDomainIntelligence(payload){
 const activity=Array.isArray(payload.activity)?payload.activity:[];
 const providers=Array.isArray(payload.search_providers)?payload.search_providers:[];
 $("domainIntelTotal").textContent=(Number(payload.observed_query_count)||0).toLocaleString();
 $("domainIntelPairs").textContent=(Number(payload.unique_device_domain_pairs)||0).toLocaleString();
 $("domainIntelSearch").textContent=providers.reduce((sum,item)=>sum+(Number(item.query_count)||0),0).toLocaleString();
 $("domainIntelRows").innerHTML=activity.map(item=>'<tr><td class="mono">'+esc(item.client_ip)+'</td><td>'+esc(item.domain)+'</td><td>'+esc(item.category)+'</td><td>'+esc(item.provider||"—")+'</td><td>'+Number(item.query_count||0)+'</td><td>'+esc(item.last_seen||"—")+'</td></tr>').join("")||'<tr><td colspan="6">No DNS domain observations in the last 7 days.</td></tr>';
 $("domainIntelLimits").textContent=(payload.limitations||[]).join(" · ");
}
function renderFullPortHistory(rows){
 $("fullPortRows").innerHTML=rows.map(item=>{
  const detail=item.detail||{},ports=Array.isArray(detail.open_ports)?detail.open_ports:(item.open_ports||[]);
  const names=Array.isArray(detail.services)?detail.services.map(s=>s.port+"/"+s.protocol+" "+[s.name,s.product,s.version].filter(Boolean).join(" ")):ports.map(p=>String(p)+"/tcp");
  return '<tr><td>'+esc(item.timestamp||"—")+'</td><td class="mono">'+esc(item.ip)+'</td><td>'+(item.completed?"COMPLETE":"INCOMPLETE")+'</td><td>'+ports.length+'</td><td title="'+esc(names.join(" · "))+'">'+esc(names.slice(0,8).join(" · ")||"No open ports observed")+(names.length>8?" · +"+(names.length-8)+" more":"")+'</td></tr>';
 }).join("")||'<tr><td colspan="5">No full-port results yet.</td></tr>';
}
async function runFullPortScan(){
 const input=$("fullPortTarget"),button=$("fullPortScanButton"),status=$("fullPortStatus"),ip=(input.value||"").trim();
 if(!ip){toast("Enter an online device IPv4 address.");input.focus();return;}
 if(!confirm("Run a full TCP scan of all 65,535 ports on "+ip+"? This is an active scan and may take several minutes. Continue only if you administer this network and have authority to scan this device."))return;
 button.disabled=true;status.textContent="Running bounded full TCP scan against "+ip+"…";
 try{
  const response=await fetch("/api/port-intelligence/scan",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({ip:ip,confirm:true})});
  const payload=await response.json();if(!response.ok)throw new Error(payload.error||("HTTP "+response.status));
  const result=payload.result||{};status.textContent="Completed "+result.ports_tested+" TCP ports in "+result.duration_seconds+"s. "+result.open_count+" open ports found: "+(result.open_ports||[]).join(", ");
  await refreshAll();
 }catch(error){status.textContent="Full scan did not complete: "+String(error.message||error);}
 finally{button.disabled=false;}
}

const SECONDARY_REFRESH_INTERVAL_MS=15000;
let lastSecondaryRefreshAt=0;
async function refreshAll(forceSecondary=false){
 if(refreshInFlight){
  if(forceSecondary){forceRefreshQueued=true;const updated=$("updated");if(updated)updated.textContent="Manual refresh queued; the current dashboard refresh will finish first.";}
  return;
 }
 refreshInFlight=true;
 void loadFirewallSnapshot(forceSecondary);
 const specs=[
  ["status","/api/status"],["devices","/api/devices"],["domains","/api/domains"],
  ["domainIntel","/api/domain-intelligence"],["fullPorts","/api/port-intelligence"],
  ["alerts","/api/alerts"],["events","/api/events"],["dns","/api/dns"],["topology","/api/topology"],
  ["progress","/api/progress"],["investigations","/api/investigations"],
  ["network","/api/network"],["diagnostics","/api/diagnostics"],
  ["engine","/api/engine_diagnostics"],["scanPerformance","/api/scan_performance"],["resilience","/api/resilience"]
 ];
 try{
  const settled=await Promise.allSettled(specs.map(([,path])=>getJSON(path,10000)));
  const data={},failed=[];
  settled.forEach((r,i)=>{const name=specs[i][0];if(r.status==="fulfilled")data[name]=r.value;else{data[name]=null;failed.push(name+": "+String(r.reason?.message||r.reason||"request failed"));}});
  const s=data.status||{},d=Array.isArray(data.devices)?data.devices:[],domains=Array.isArray(data.domains)?data.domains:[],a=Array.isArray(data.alerts)?data.alerts:[],e=Array.isArray(data.events)?data.events:[],inv=Array.isArray(data.investigations)?data.investigations:[],dnsRows=Array.isArray(data.dns)?data.dns:[],topology=data.topology||{},n=data.network||{},diag=data.diagnostics||{},eng=data.engine||{},j=data.progress||{},sp=data.scanPerformance||{};
  const statusOK=!!data.status;
  const partial=failed.length>0||!!s.status_degraded;
  pill($("connection"),!statusOK?"API DEGRADED":(partial?"CONNECTED · PARTIAL":"CONNECTED"),!statusOK?"bad":(partial?"warn":"ok"));
  if(!statusOK){$("updated").textContent="Status API unavailable. "+failed.join(" | ");}
  else{
   const issues=[...failed,...(s.status_errors||[])];
   $("updated").textContent="Updated "+(s.timestamp||new Date().toLocaleTimeString())+(issues.length?" · "+issues.slice(0,4).join(" | "):"");
  }
  $("network").textContent=s.network||n.network||"—";$("activeSubnet").textContent=n.network||s.network||"—";
  $("defaultGateway").textContent=n.gateway||"—";const ncHost=$("ncRouterHost");if(ncHost&&!ncHost.value&&n.gateway)ncHost.value=n.gateway;$("fingerprint").textContent=n.fingerprint||"—";$("fpConf").textContent=(n.confidence||0)+"%";
  $("networkWarning").textContent=n.warning||(n.authorized?"Authorised.":"Passive only.");$("authorizeNetwork").style.display=n.authorized?"none":"inline-block";$("netAuthz").textContent=n.auth_decision||"—";
  $("jobPhase").textContent=j.phase||"—";$("jobMessage").textContent=j.message||"Waiting for engine status.";$("jobPercent").textContent=(j.percent??0)+"%";$("jobBar").style.width=(j.percent??0)+"%";renderScanMonitor(j);renderResilience(data.resilience||{});
  $("online").textContent=s.online??"—";$("historical").textContent=s.historical??"—";$("deviceHint").textContent=(s.offline??"—")+" offline";$("openInvestigations").textContent=s.open_investigations??inv.length;
  const nr=$("networkRisk");nr.textContent=s.network_risk_band||"UNKNOWN";nr.className="value risk-"+(s.network_risk_band||"UNKNOWN");
  pill($("dnsStatus"),s.dns_status||"UNKNOWN",s.dns_status==="ONLINE"?"ok":"warn");pill($("dhcpStatus"),s.dhcp_status||"UNKNOWN",s.dhcp_status==="ONLINE"?"ok":"warn");pill($("arpStatus"),s.arp_status||"UNKNOWN",s.arp_status==="ONLINE"?"ok":"warn");
  const dhcp=eng.engines?.dhcp||{};$("dhcpClass").textContent=(dhcp.state||"UNKNOWN")+" — "+(dhcp.reason||"");$("dhcpClass").title=dhcp.reason||"No DHCP diagnostic detail returned.";const resilienceEngine=eng.engines?.network_resilience||{};pill($("resilienceEngineStatus"),resilienceEngine.state||"STARTING",resilienceEngine.state==="ONLINE"?"ok":resilienceEngine.state==="DEGRADED"?"warn":"bad");
  $("dbQueue").textContent=(s.db_health?.queued??"—")+" queued, "+(s.db_health?.processed??"—")+" done";const quality=diag.scan_quality||{},coverage=quality.identity_coverage||{},identityCoverage=coverage.available===false?"—":((coverage.coverage_percent??"—")+"%");$("scanQuality").textContent=(quality.score??"—")+"/100 · "+(quality.band||"—")+" · Identity "+identityCoverage;
  if(data.devices){deviceCache=d;filterDevices();renderNetworkControlDeviceOptions(d);}else{$("deviceRows").innerHTML='<tr><td colspan="8">Device API unavailable. Check server log and /api/devices.</td></tr>';}
  $("domainRows").innerHTML=domains.map(x=>`<tr><td class="mono">${esc(x.domain)}</td><td>${x.query_count}</td><td>${esc(x.risk_level)}</td></tr>`).join("")||'<tr><td colspan="3">—</td></tr>';
  renderDomainIntelligence(data.domainIntel||{});
  renderFullPortHistory(Array.isArray(data.fullPorts)?data.fullPorts:[]);
  $("alertRows").innerHTML=a.map(x=>`<tr><td>${esc(x.timestamp)}</td><td class="mono">${esc(x.client_ip)}</td><td>${esc(x.rule_id)}</td><td class="${x.severity==="HIGH"?"red":"amber"}">${esc(x.severity)}</td></tr>`).join("")||'<tr><td colspan="4">—</td></tr>';
  $("eventRows").innerHTML=e.map(x=>`<tr><td>${esc(x.timestamp)}</td><td class="mono">${esc(x.ip)}</td><td>${esc(x.category)}</td><td>${esc(x.event_type)}</td><td>${esc(x.details)}</td></tr>`).join("")||'<tr><td colspan="5">—</td></tr>';
  renderIdentityTimeline(e);
  renderNightwatch(s,n,d,dnsRows,a,e,topology);
  const perfSummary=$("scanPerformanceSummary"),perfRows=$("scanPhaseRows");
  if(perfSummary){
   perfSummary.textContent=sp.available
    ? "Scan #"+(sp.scan_number||"—")+" · "+(sp.total_duration_seconds||0)+"s · "+(sp.device_count??"—")+" hosts · "+(sp.completed?"completed":"partial")
    : (sp.message||"No scan timing data yet.");
  }
  if(perfRows){
   perfRows.innerHTML=(sp.phases||[]).map(function(x){return '<tr><td>'+esc(x.name)+'</td><td>'+esc(x.calls)+'</td><td>'+esc(x.duration_seconds)+'s</td><td>'+esc(x.last_duration_seconds)+'s</td><td>'+esc(x.errors)+(x.last_error_type?' · '+esc(x.last_error_type):'')+'</td></tr>';}).join('')||'<tr><td colspan="5">Run a scan to collect phase timings.</td></tr>';
  }
  $("behaviourStatus").textContent=diag.behaviour?.message||"Behaviour diagnostics unavailable.";
  $("behaviourRows").innerHTML=((diag.behaviour?.baseline_devices||0)>0?'<tr><td colspan="5">See device detail for samples.</td></tr>':'<tr><td colspan="5">Collecting baselines.</td></tr>');
  $("investigationRows").innerHTML=inv.map(x=>`<tr><td>${esc(x.timestamp)}</td><td>${esc(x.title)}</td><td>${esc(x.severity)}</td><td>${esc(x.status)}</td><td>${esc(x.evidence_count)}</td></tr>`).join("")||'<tr><td colspan="5">None.</td></tr>';
  const now=Date.now();
  if(forceSecondary||now-lastSecondaryRefreshAt>=SECONDARY_REFRESH_INTERVAL_MS){
   lastSecondaryRefreshAt=now;
   loadNetworkWorkspaces();loadProfiles();loadChanges();loadConfig();loadAlertStream();loadIdentityIntel();loadContinuity();loadCandidates();loadPhantomPanels();
  }
  loadNetworkControlStatus();
 }catch(err){pill($("connection"),"DASHBOARD ERROR","bad");$("updated").textContent=err.message||String(err);}
 finally{
  refreshInFlight=false;
  if(forceRefreshQueued){
   forceRefreshQueued=false;
   // Start immediately so a second click cannot race this queued refresh.
   void refreshAll(true);
  }
 }
}
loadHuntTemplates();refreshAll();setInterval(refreshAll,5000);
// Searchable, collapsible navigation with deterministic desktop/mobile state.
const nrNavMedia = window.matchMedia('(max-width: 900px)');
function syncNavigationButton(){
 const b=document.getElementById('navToggle');
 if(!b)return;
 const mobile=nrNavMedia.matches;
 const expanded=mobile?document.body.classList.contains('nav-open'):!document.body.classList.contains('nav-collapsed');
 b.setAttribute('aria-expanded',expanded?'true':'false');
 b.setAttribute('aria-label',mobile?(expanded?'Close navigation':'Open navigation'):(expanded?'Collapse navigation':'Expand navigation'));
 b.title=mobile?(expanded?'Close navigation':'Open navigation'):(expanded?'Collapse navigation':'Expand navigation');
 b.textContent=mobile?(expanded?'✕':'☰'):(expanded?'☰':'»');
}
/* WORKSPACE LAYOUT — group existing panels without removing IDs, data or handlers. */
(function buildWorkspaceLayout(){
 const main=document.querySelector('main');
 if(!main||main.dataset.workspaceReady==='1')return;
 const definitions=[
  {id:'command',label:'Command Centre',desc:'Live network picture, scan status, topology and current network context.'},
  {id:'devices',label:'Devices & Identity',desc:'Device inventory, identity evidence, unknown-device review and IPv6 neighbours.'},
  {id:'network',label:'Network Activity',desc:'Network workspaces, profiles, DNS, DHCP, ARP, behaviour and change history.'},
  {id:'control',label:'Network Control',desc:'Router-enforced bandwidth limits, timed device pauses and network-wide internet control.'},
  {id:'security',label:'Security & Investigations',desc:'Firewall visibility, alerts, configuration audit, threat hunts and exposure.'},
 ];
 const groups=Object.fromEntries(definitions.map(x=>[x.id,[]]));
 const overviewIds=new Set(['top','topology','activity','cmd']);
 const deviceIds=new Set(['devices','identity','continuity','candidates','unknownHunter','identitySubscan','ipv6','phantomAccess','commandCenter']);
 const networkIds=new Set(['networkWorkspaces','profiles','dns','domainIntelligence','fullPortIntelligence','dhcp','arp','behaviour','changes']);
 const controlIds=new Set(['networkControl']);
 const securityIds=new Set(['firewall','investigations','alerts','config','hunt','exposure','assistant','reports']);
 function classify(node){
  const id=node.id||'';
  if(overviewIds.has(id)||node.classList.contains('nightwatch-metrics')||node.classList.contains('nw-inventory-status')||node.querySelector('#jobPhase,#online,#engines'))return 'command';
  if(deviceIds.has(id))return 'devices';
  if(networkIds.has(id))return 'network';
   if(controlIds.has(id))return 'control';
  if(securityIds.has(id))return 'security';
  if(node.querySelector('#eventRows'))return 'security';
  return 'command';
 }
 const original=[...main.children];
 original.forEach(node=>groups[classify(node)].push(node));
 const switcher=document.createElement('div');
 switcher.className='nr-workspace-switcher';
 switcher.setAttribute('role','tablist');
 switcher.setAttribute('aria-label','NetworkRadar workspaces');
 switcher.innerHTML=definitions.map((x,i)=>'<button type="button" class="nr-workspace-tab" role="tab" id="tab-workspace-'+x.id+'" aria-controls="workspace-'+x.id+'" aria-selected="'+(i===0?'true':'false')+'" data-workspace-tab="'+x.id+'"><span class="nr-tab-index">0'+(i+1)+'</span><span class="nr-tab-copy"><b>'+x.label+'</b><small>'+x.desc+'</small></span></button>').join('');
 main.appendChild(switcher);
 definitions.forEach((x,i)=>{
  const panel=document.createElement('div');
  panel.id='workspace-'+x.id;
  panel.className='nr-workspace-panel';
  panel.setAttribute('role','tabpanel');
  panel.setAttribute('aria-labelledby','tab-workspace-'+x.id);
  panel.dataset.workspacePanel=x.id;
  if(i!==0)panel.hidden=true;
  groups[x.id].forEach(node=>panel.appendChild(node));
  main.appendChild(panel);
 });
 main.dataset.workspaceReady='1';
 function panelForHash(){
  const hash=decodeURIComponent((location.hash||'').slice(1));
  if(!hash)return 'command';
  const target=document.getElementById(hash);
  const panel=target?.closest('[data-workspace-panel]');
  return panel?.dataset.workspacePanel||(/^(workspace-)?(command|devices|network|control|security|management|intelligence)$/.test(hash)?hash.replace('workspace-',''):'command');
 }
 window.activateNetworkRadarWorkspace=function(id,updateHash){
  const key=definitions.some(x=>x.id===id)?id:'command';
  document.querySelectorAll('[data-workspace-panel]').forEach(p=>p.hidden=p.dataset.workspacePanel!==key);
  switcher.querySelectorAll('[data-workspace-tab]').forEach(b=>{
   const active=b.dataset.workspaceTab===key;
   b.setAttribute('aria-selected',active?'true':'false');
   b.tabIndex=active?0:-1;
  });
  document.querySelectorAll('#sideNavigation a[href^="#workspace-"]').forEach(a=>a.classList.toggle('active',a.getAttribute('href')==='#workspace-'+key));
  try{localStorage.setItem('nr-active-workspace',key);}catch(e){}
  if(updateHash!==false&&location.hash!=='#workspace-'+key)history.replaceState(null,'','#workspace-'+key);
 };
 switcher.addEventListener('click',e=>{
  const button=e.target.closest('[data-workspace-tab]');
  if(button)window.activateNetworkRadarWorkspace(button.dataset.workspaceTab,true);
 });
 switcher.addEventListener('keydown',e=>{
  if(!['ArrowLeft','ArrowRight','Home','End'].includes(e.key))return;
  const buttons=[...switcher.querySelectorAll('[data-workspace-tab]')];
  const current=buttons.findIndex(b=>b.getAttribute('aria-selected')==='true');
  const next=e.key==='Home'?0:e.key==='End'?buttons.length-1:(current+(e.key==='ArrowRight'?1:-1)+buttons.length)%buttons.length;
  e.preventDefault();buttons[next].focus();window.activateNetworkRadarWorkspace(buttons[next].dataset.workspaceTab,true);
 });
 window.activateNetworkRadarWorkspace(panelForHash(),false);
 window.addEventListener('hashchange',()=>window.activateNetworkRadarWorkspace(panelForHash(),false));
})();
function toggleNavigation(){
 if(nrNavMedia.matches){
  document.body.classList.toggle('nav-open');
  if(document.body.classList.contains('nav-open')){
   const first=document.querySelector('#sideNavigation a:not([hidden])');
   if(first)window.setTimeout(()=>first.focus(),80);
  }
 }else{
  document.body.classList.remove('nav-open');
  document.body.classList.toggle('nav-collapsed');
  try{localStorage.setItem('nr-nav-collapsed',document.body.classList.contains('nav-collapsed')?'1':'0');}catch(e){}
 }
 syncNavigationButton();
}
function closeNavigation(){
 document.body.classList.remove('nav-open');
 syncNavigationButton();
}
(function initNavigation(){
 try{if(localStorage.getItem('nr-nav-collapsed')==='1'&&!nrNavMedia.matches)document.body.classList.add('nav-collapsed');}catch(e){}
 const search=document.getElementById('navSearch'),nav=document.getElementById('sideNavigation'),empty=document.getElementById('navEmpty');
 if(search&&nav){
  search.addEventListener('input',()=>{
   const q=search.value.trim().toLowerCase();let shown=0;
   nav.querySelectorAll("a[href^='#']").forEach(a=>{const hit=!q||a.textContent.toLowerCase().includes(q);a.hidden=!hit;if(hit)shown++;});
   nav.querySelectorAll('.nav-group').forEach(g=>{let n=g.nextElementSibling,has=false;while(n&&!n.classList.contains('nav-group')){if(n.matches('a')&&!n.hidden)has=true;n=n.nextElementSibling;}g.hidden=!!q&&!has;});
   if(empty)empty.style.display=shown?'none':'block';
  });
  nav.querySelectorAll("a[href^='#']").forEach(a=>a.addEventListener('click',()=>{closeNavigation();if(search){search.value='';search.dispatchEvent(new Event('input'));}}));
 }
 document.addEventListener('keydown',e=>{if(e.key==='Escape')closeNavigation();});
 window.addEventListener('resize',()=>{if(!nrNavMedia.matches)document.body.classList.remove('nav-open');syncNavigationButton();});
 if(typeof nrNavMedia.addEventListener==='function')nrNavMedia.addEventListener('change',()=>{document.body.classList.remove('nav-open');syncNavigationButton();});
 syncNavigationButton();
})();
// Keep the navigation highlight aligned with the section currently in view.
if("IntersectionObserver" in window){
 const navLinks=[...document.querySelectorAll("#sideNavigation a[href^='#']")];
 const sections=navLinks.map(a=>document.querySelector(a.getAttribute("href"))).filter(Boolean);
 const navObserver=new IntersectionObserver(entries=>{
  const visible=entries.filter(e=>e.isIntersecting).sort((a,b)=>b.intersectionRatio-a.intersectionRatio)[0];
  if(!visible)return;navLinks.forEach(a=>a.classList.toggle("active",a.getAttribute("href")==="#"+visible.target.id));
 },{rootMargin:"-16% 0px -70% 0px",threshold:[0,.12,.3]});
 sections.forEach(section=>navObserver.observe(section));
}

async function loadPhantomPanels(){
 try{
  const [u,v,x,sub]=await Promise.all([fetch('/api/unknown-hunter').then(r=>r.json()),fetch('/api/ipv6').then(r=>r.json()),fetch('/api/exposure').then(r=>r.json()),fetch('/api/identity/subscan').then(r=>r.json())]);
  $('unknownRows').innerHTML=u.map(d=>{const plan=d.identity_guidance?.investigation_plan||{};const next=plan.planned?.[0];const deferred=plan.deferred?.find(x=>["COOLDOWN","RUNNING","EXHAUSTED","COLLECTOR_UNAVAILABLE","AUTHORIZATION_REQUIRED","WAITING_FOR_ONLINE"].includes(x.state))||plan.deferred?.[0];const method=next?(next.label+" · "+next.mode):(deferred?(deferred.method+" · "+deferred.state):"No eligible method");return '<tr><td class="mono">'+esc(d.ip)+'</td><td>'+esc(d.name)+'</td><td>'+esc(d.device_type)+'</td><td>'+esc(d.os_guess)+'</td><td>'+d.confidence+'%</td><td>'+d.evidence_count+' / '+d.independent_sources+' sources</td><td title="'+esc((d.next_steps||[]).join(" | "))+'">'+esc((d.next_steps||[])[0]||"Collect more evidence")+'</td><td>'+esc(method)+'</td><td>'+esc(d.status)+'</td></tr>'}).join('')||'<tr><td colspan="9">No low-confidence devices in current inventory.</td></tr>';
  const counts=sub.counts||{};$('subscanQueued').textContent=counts.queued??0;$('subscanRunning').textContent=counts.running??0;$('subscanResolved').textContent=counts.resolved??0;$('subscanExhausted').textContent=counts.exhausted??0;$('subscanAttempted').textContent=sub.attempted_targets??0;
  pill($('subscanWorkerState'),sub.worker_alive?'WORKER ONLINE':(sub.paused?'PAUSED':'WORKER OFFLINE'),sub.worker_alive?'ok':'warn');
  $('subscanPolicy').textContent='Maximum '+(sub.max_attempts_per_target||3)+' attempts per target · exponential backoff · next due in '+(sub.next_due_in_seconds==null?'—':Math.ceil(sub.next_due_in_seconds)+'s')+'. Active probing only on the explicitly authorised current private subnet.';
  const sp=sub.progress||{};const currentPct=Math.max(0,Math.min(100,Number(sp.percent)||0));const running=sp.state==='RUNNING';const completed=sp.state==='COMPLETED';
  $('subscanCurrentBar').style.width=(running||completed||sp.state==='QUEUED'||sp.state==='EXHAUSTED')?currentPct+'%':'0%';
  $('subscanCurrentBar').classList.toggle('is-running',running);
  $('subscanCurrentPercent').textContent=(running||completed||sp.state==='QUEUED'||sp.state==='EXHAUSTED')?currentPct+'%':'0%';
  $('subscanCurrentTarget').textContent=sp.ip?(running?'INVESTIGATING '+sp.ip:(completed?'LAST COMPLETED · '+sp.ip:'LAST ATTEMPT · '+sp.ip)):'No device currently being investigated';
  $('subscanCurrentDetail').textContent=(sp.phase||'Waiting for an unidentified device')+(sp.message?' · '+sp.message:'');
  const queuePct=Math.max(0,Math.min(100,Number(sub.queue_progress_percent)||0));$('subscanQueueBar').style.width=queuePct+'%';$('subscanQueuePercent').textContent=queuePct+'%';
  $('subscanQueueDetail').textContent=(sub.processed_targets||0)+' of '+(sub.total_targets||0)+' targets processed · '+(counts.queued||0)+' queued · '+(counts.running||0)+' running';
  $('subscanRows').innerHTML=(sub.targets||[]).map(t=>'<tr><td class="mono">'+esc(t.ip)+'</td><td>'+esc(t.state)+'</td><td>'+esc(t.attempts)+'</td><td>'+esc(t.next_attempt_at?new Date(t.next_attempt_at*1000).toLocaleTimeString():'—')+'</td><td>'+esc(t.last_error||'—')+'</td></tr>').join('')||'<tr><td colspan="5">No devices currently queued for follow-up.</td></tr>';
  $('ipv6Rows').innerHTML=v.map(d=>`<tr><td class="mono">${esc(d.ipv6)}</td><td class="mono">${esc(d.mac||'—')}</td><td>${esc(d.interface_alias||'—')}</td><td>${esc(d.state)}</td><td>${esc(d.timestamp)}</td><td>${esc(d.linked_device_id||'Uncorrelated')}</td></tr>`).join('')||'<tr><td colspan="6">No IPv6 neighbour observations recorded.</td></tr>';
  $('exposureRows').innerHTML=x.map(d=>`<tr><td class="mono">${esc(d.ip)}</td><td>${esc(d.title)}</td><td class="${d.severity==='HIGH'?'red':'amber'}">${esc(d.severity)}</td><td>${esc(d.observed_ports)}</td><td>${esc(d.recommendation)}</td><td>${esc(d.last_seen)}</td><td>${esc(d.status)}</td></tr>`).join('')||'<tr><td colspan="7">No current or stale exposure observations.</td></tr>';
 }catch(e){$('unknownRows').innerHTML='<tr><td colspan="8">Panel unavailable: '+esc(e.message)+'</td></tr>';}
}
async function investigateUnknown(){
 const status=$("unknownInvestigationStatus");status.textContent="Reviewing local identity evidence…";
 try{const r=await fetch("/api/unknown-hunter/investigate",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({confirm:true,limit:50})});
  const data=await r.json();if(!r.ok)throw new Error(data.error||("HTTP "+r.status));
  status.textContent=`Created ${data.created} new and updated ${data.updated} identity-review investigations. These are not threat findings.`;
  await refreshAll();
 }catch(e){status.textContent="Investigation failed: "+e.message;}
}
async function askRadar(){
 const q=$('assistantQuestion').value.trim(); if(!q)return;
 $('assistantAnswer').textContent='Analysing local evidence…';
 try{const r=await fetch('/api/assistant?q='+encodeURIComponent(q)).then(x=>x.json());$('assistantAnswer').textContent=r.answer||r.error||'No answer';
 const rows=(r.results||[]).slice(0,50);$('assistantRows').innerHTML=rows.map(obj=>`<tr><td>${esc(obj.ip||obj.ipv6||obj.name||'Record')}</td><td>${esc(Object.entries(obj).filter(([k])=>!['ip','ipv6','name'].includes(k)).map(([k,v])=>k+': '+(typeof v==='object'?JSON.stringify(v):v)).join(' · '))}</td></tr>`).join('')||'<tr><td colspan="2">No supporting records returned.</td></tr>';
 }catch(e){$('assistantAnswer').textContent='Assistant error: '+e.message;}
}
$('assistantQuestion')?.addEventListener('keydown',e=>{if(e.key==='Enter')askRadar();});

let phantomSelectedIP="";
let phantomSshFingerprint="";
let phantomSshTrusted=false;
let phantomSshSession="";
let phantomSshSessionTarget="";
let phantomSshTrustedTarget="";
let phantomSshSocket=null;
let phantomSshResizeObserver=null;
let phantomTerminalBuffer='';
let phantomTerminalCursor=0;
let phantomTerminalPendingCR=false;
function updatePhantomSelectionCount(){
 const selected=document.querySelectorAll('.pa-device-check:checked').length;
 const total=document.querySelectorAll('.pa-device-check:not(:disabled)').length;
 const el=$('paSelectionCount');if(el)el.textContent=`${selected} selected · ${total} online`;
 const all=$('paSelectAll');if(all){all.checked=total>0&&selected===total;all.indeterminate=selected>0&&selected<total;}
}
async function loadPhantomAccess(){
 const body=$('phantomAccessRows'); if(!body)return;
 const previous=new Set([...document.querySelectorAll('.pa-device-check:checked')].map(x=>x.value));
 body.innerHTML='<tr><td colspan="11">Loading known devices and previous capability observations…</td></tr>';
 try{
  const [data,summary]=await Promise.all([getJSON('/api/phantom-access/devices'),getJSON('/api/phantom-access/summary')]);
  $('paKnown').textContent=summary.known||0;$('paCandidates').textContent=summary.native_candidates||0;$('paSshReachable').textContent=summary.ssh_reachable||0;$('paRdp').textContent=summary.rdp_reachable||0;$('paAgents').textContent=summary.agent_managed||0;
  body.innerHTML=(data||[]).map(d=>{const p=d.probes||{};const yes=v=>v===true?'<span class="green">OPEN</span>':v===false?'<span class="muted">CLOSED</span>':'<span class="muted">—</span>';const online=d.status==='ONLINE';const checked=previous.has(d.ip);return `<tr data-pa-row="${esc(d.ip)}"><td><input type="checkbox" class="pa-device-check" value="${esc(d.ip)}" ${online?'':'disabled'} ${checked?'checked':''} aria-label="Select ${esc(d.ip)}"></td><td><strong>${esc(d.hostname||d.friendly_name||d.device_name||'Unknown')}</strong><div class="hint">${esc(d.manufacturer||'')} ${esc(d.model||'')}</div></td><td>${esc(d.device_type||'Unclassified')}<div class="hint">${esc(d.os_guess||'Unknown')}</div></td><td class="mono">${esc(d.ip)}</td><td>${yes(p.winrm_http||p.winrm_https)}</td><td>${yes(p.rpc_endpoint_mapper)}</td><td>${yes(p.smb)}</td><td>${yes(p.rdp)}</td><td>${yes(p.ssh)}</td><td><span class="pill ${d.readiness==='NATIVE_MGMT_CANDIDATE'?'':'warn'}">${esc(d.readiness||'NOT_PROBED')}</span><div class="hint">${esc(d.readiness_score??0)}% · ${esc(d.last_probe||'Not probed')}</div></td><td class="pa-row-actions"><button class="secondary" data-pa-action="probe" data-ip="${esc(d.ip)}">PROBE</button> <button class="secondary" data-pa-action="select" data-ip="${esc(d.ip)}">SELECT</button> <button class="secondary" data-pa-action="terminal" data-ip="${esc(d.ip)}" ${p.ssh===true&&online?'':'disabled'}>SSH TERMINAL</button></td></tr>`}).join('')||'<tr><td colspan="11">No known devices in inventory yet. Run a network scan first.</td></tr>';
  updatePhantomSelectionCount();
 }catch(e){body.innerHTML=`<tr><td colspan="11">Could not load Phantom Access: ${esc(e.message)}</td></tr>`;}
}
function toggleAllPhantom(on){document.querySelectorAll('.pa-device-check:not(:disabled)').forEach(x=>x.checked=on);updatePhantomSelectionCount();}
function selectedPhantomIPs(){return [...document.querySelectorAll('.pa-device-check:checked')].map(x=>x.value);}
async function phantomBulk(action){
 const ips=selectedPhantomIPs();if(!ips.length){alert('Select at least one online endpoint.');return;}
 const labels={probe:'probe',remote_inventory:'refresh system inventory',remote_network:'collect network snapshots',remote_storage:'collect storage snapshots',remote_security:'collect security snapshots'};
 if(!confirm(`Run ${labels[action]||action} on all ${ips.length} selected endpoint(s)? Work will be split into batches of 12 and every result will be recorded.`))return;
 $('paStatus').textContent=`Preparing ${ips.length} endpoint(s)…`;$('paOutput').textContent='';
 const aggregate={action,requested:ips.length,succeeded:0,failed:0,batches:[],results:[]};
 try{
  for(let offset=0;offset<ips.length;offset+=12){
   const batch=ips.slice(offset,offset+12);$('paStatus').textContent=`${action.replaceAll('_',' ')} · batch ${Math.floor(offset/12)+1}/${Math.ceil(ips.length/12)} · ${Math.min(offset+batch.length,ips.length)}/${ips.length} endpoints`;
   try{const r=await fetch('/api/phantom-access/bulk',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ips:batch,action})});const d=await r.json();if(!r.ok)throw new Error(d.error||r.status);
    aggregate.succeeded+=d.succeeded||0;aggregate.failed+=d.failed||0;aggregate.batches.push({batch:Math.floor(offset/12)+1,requested:d.requested,succeeded:d.succeeded,failed:d.failed});aggregate.results.push(...(d.results||[]));
   }catch(batchError){aggregate.failed+=batch.length;aggregate.batches.push({batch:Math.floor(offset/12)+1,requested:batch.length,succeeded:0,failed:batch.length,error:batchError.message});aggregate.results.push(...batch.map(ip=>({ip,success:false,error:'Batch request failed: '+batchError.message})));}
   $('paOutput').textContent=JSON.stringify(aggregate,null,2);
  }
  $('paStatus').textContent=`Bulk ${action}: ${aggregate.succeeded} succeeded · ${aggregate.failed} failed · ${aggregate.requested} requested.`;toast(`Phantom Access: ${aggregate.succeeded}/${aggregate.requested} completed.`);await loadPhantomAccess();
 }catch(e){$('paStatus').textContent='Bulk operation interrupted: '+e.message;$('paOutput').textContent=JSON.stringify(aggregate,null,2)+'\n\n'+e.message;}
}
function selectPhantom(ip){if(phantomSshSessionTarget&&phantomSshSessionTarget!==ip&&phantomSshSocket&&phantomSshSocket.readyState<2){if(!confirm('Disconnect the active SSH terminal before switching to '+ip+'?'))return;sshDisconnect();}phantomSelectedIP=ip;$('paTarget').textContent=ip;$('paSshIp').value=ip;phantomSshFingerprint='';phantomSshTrusted=false;phantomSshTrustedTarget='';$('paSshFingerprint').textContent='Host key not reviewed for this endpoint.';$('paSshTrustBtn').disabled=true;$('paSshConnectBtn').disabled=true;$('paStatus').textContent='Selected '+ip+'. Probe capabilities before attempting a remote operation.';}
async function probePhantom(ip){selectPhantom(ip);$('paStatus').textContent='Testing management service reachability…';try{const r=await fetch('/api/phantom-access/probe',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip,confirm:true})});const d=await r.json();if(!r.ok)throw new Error(d.error||r.status);$('paMethod').textContent=d.readiness;$('paStatus').textContent=d.summary;$('paOutput').textContent=JSON.stringify(d,null,2);await loadPhantomAccess();}catch(e){$('paStatus').textContent='Probe failed: '+e.message;}}
async function phantomAction(action){
 if(!phantomSelectedIP){alert('Select a known device first.');return;}
 let args={};if(action==='restart_service'){const n=prompt('Exact Windows service name to restart:');if(!n)return;args.service_name=n;}
 const disruptive=['restart_service','restart_computer','shutdown_computer'];
 if(disruptive.includes(action)&&!confirm(`Run ${action.replaceAll('_',' ')} on ${phantomSelectedIP} using your current Windows account? This action will be audited.`))return;
 $('paStatus').textContent='Executing '+action+' using native Windows management…';
 try{const r=await fetch('/api/phantom-access/action',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip:phantomSelectedIP,action,args,confirm:disruptive.includes(action)})});const d=await r.json();if(!r.ok)throw new Error(d.error||r.status);$('paLastAction').textContent=action+' · '+(d.method||'');$('paMethod').textContent=d.method||$('paMethod').textContent;$('paOutput').textContent=JSON.stringify(d,null,2);$('paStatus').textContent=d.message||'Operation completed.';await loadPhantomAccess();}catch(e){$('paStatus').textContent='Operation failed: '+e.message;$('paOutput').textContent=e.message;}
}
async function sshApi(path,payload){const r=await fetch('/api/phantom-access/ssh/'+path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});const d=await r.json();if(!r.ok)throw new Error(d.error||`HTTP ${r.status}`);return d;}
function sshSetState(text,state='warn'){pill($('paSshState'),text,state);}
function sshAppend(text){
 const out=$('paTerminalOutput');let raw=String(text).replace(/\x1b\][^\x07]*(?:\x07|\x1b\\)/g,'');raw=raw.replace(/\x1b\[([0-?]*)([ -/]*)([@-~])/g,(seq,params,inter,final)=>{if(final==='J'&&params==='2'){phantomTerminalBuffer='';phantomTerminalCursor=0;phantomTerminalPendingCR=false;}else if((final==='H'||final==='f')&&!params){phantomTerminalCursor=0;}else if(final==='K'){phantomTerminalBuffer=phantomTerminalBuffer.slice(0,phantomTerminalCursor);}return '';});const clean=raw;
 for(const ch of clean){
  if(ch==='\r'){const lineStart=phantomTerminalBuffer.lastIndexOf('\n',Math.max(0,phantomTerminalCursor-1))+1;phantomTerminalCursor=lineStart;phantomTerminalPendingCR=true;continue;}
  if(ch==='\n'){
   if(phantomTerminalPendingCR){phantomTerminalBuffer+='\n';phantomTerminalCursor=phantomTerminalBuffer.length;}
   else{phantomTerminalBuffer=phantomTerminalBuffer.slice(0,phantomTerminalCursor)+'\n'+phantomTerminalBuffer.slice(phantomTerminalCursor);phantomTerminalCursor++;}
   phantomTerminalPendingCR=false;continue;
  }
  if(phantomTerminalPendingCR){phantomTerminalBuffer=phantomTerminalBuffer.slice(0,phantomTerminalCursor);phantomTerminalPendingCR=false;}
  if(ch==='\b'){
   const lineStart=phantomTerminalBuffer.lastIndexOf('\n',Math.max(0,phantomTerminalCursor-1))+1;
   if(phantomTerminalCursor>lineStart){phantomTerminalBuffer=phantomTerminalBuffer.slice(0,phantomTerminalCursor-1)+phantomTerminalBuffer.slice(phantomTerminalCursor);phantomTerminalCursor--;}
   continue;
  }
  if(ch==='\t'){const spaces=4-(phantomTerminalCursor-(phantomTerminalBuffer.lastIndexOf('\n')+1))%4;for(let i=0;i<spaces;i++){phantomTerminalBuffer=phantomTerminalBuffer.slice(0,phantomTerminalCursor)+' '+phantomTerminalBuffer.slice(phantomTerminalCursor);phantomTerminalCursor++;}continue;}
  const code=ch.charCodeAt(0);if(code<32||code===127)continue;
  if(phantomTerminalCursor<phantomTerminalBuffer.length&&phantomTerminalBuffer[phantomTerminalCursor]!=='\n')phantomTerminalBuffer=phantomTerminalBuffer.slice(0,phantomTerminalCursor)+ch+phantomTerminalBuffer.slice(phantomTerminalCursor+1);
  else phantomTerminalBuffer=phantomTerminalBuffer.slice(0,phantomTerminalCursor)+ch+phantomTerminalBuffer.slice(phantomTerminalCursor);
  phantomTerminalCursor++;
 }
 if(phantomTerminalBuffer.length>220000){const trim=phantomTerminalBuffer.length-180000;phantomTerminalBuffer=phantomTerminalBuffer.slice(trim);phantomTerminalCursor=Math.max(0,phantomTerminalCursor-trim);}
 out.textContent=phantomTerminalBuffer;out.scrollTop=out.scrollHeight;
}
async function sshReviewHostKey(){
 const ip=$('paSshIp').value||phantomSelectedIP;if(!ip){alert('Select an online endpoint first.');return;}
 try{$('paSshFingerprintBtn').disabled=true;$('paSshFingerprint').textContent='Performing SSH protocol handshake…';phantomSshFingerprint='';phantomSshTrusted=false;$('paSshTrustBtn').disabled=true;$('paSshConnectBtn').disabled=true;
  const d=await sshApi('hostkey',{ip,port:Number($('paSshPort').value||22)});phantomSshFingerprint=d.fingerprint;phantomSshTrustedTarget='';$('paSshFingerprint').textContent=`${d.key_type}\n${d.fingerprint}\n\nVerify this fingerprint on the target device through a trusted channel before accepting it.`;$('paSshTrustBtn').disabled=false;toast('SSH host key retrieved. Verify the fingerprint before trusting it.');
 }catch(e){$('paSshFingerprint').textContent='Host-key review failed: '+e.message;$('paStatus').textContent=e.message;}finally{$('paSshFingerprintBtn').disabled=false;}
}
async function sshTrustHostKey(){
 if(!phantomSshFingerprint||!confirm('Trust this exact SSH server fingerprint for this IP and port? Only continue after independently verifying it.'))return;
 try{$('paSshTrustBtn').disabled=true;const d=await sshApi('trust',{ip:$('paSshIp').value,port:Number($('paSshPort').value||22),fingerprint:phantomSshFingerprint,confirm:true});phantomSshTrusted=!!d.trusted;phantomSshTrustedTarget=($('paSshIp').value||phantomSelectedIP)+':'+Number($('paSshPort').value||22);$('paSshConnectBtn').disabled=!phantomSshTrusted;sshAppend(`\n[TRUSTED HOST KEY] ${d.fingerprint}\n`);toast('SSH host key trusted. You can now authenticate.');}
 catch(e){$('paSshTrustBtn').disabled=false;$('paSshConnectBtn').disabled=true;$('paStatus').textContent='Host-key trust failed: '+e.message;}
}
function sshAuthFields(){const mode=$('paSshAuth').value;$('paSshKeyWrap').hidden=mode!=='key';$('paSshPassphraseWrap').hidden=mode!=='key';$('paSshPasswordWrap').hidden=mode!=='password';}
async function sshConnect(){
 const targetIp=$('paSshIp').value||phantomSelectedIP;const targetPort=Number($('paSshPort').value||22);if(!phantomSshTrusted||phantomSshTrustedTarget!==targetIp+':'+targetPort){alert('Review and trust the SSH host key for this exact IP and port first.');return;}
 const payload={ip:targetIp,port:targetPort,username:$('paSshUser').value,auth_type:$('paSshAuth').value};
 if(payload.auth_type==='password')payload.password=$('paSshPassword').value;
 if(payload.auth_type==='key'){payload.key_path=$('paSshKey').value;payload.passphrase=$('paSshPassphrase').value;}
 try{$('paSshConnectBtn').disabled=true;sshSetState('AUTHENTICATING','warn');phantomTerminalBuffer='';phantomTerminalCursor=0;phantomTerminalPendingCR=false;$('paTerminalOutput').textContent='Connecting to authenticated SSH shell…\n';
  const d=await sshApi('connect',payload);phantomSshSession=d.session_token;phantomSshSessionTarget=targetIp;$('paSshPassword').value='';$('paSshPassphrase').value='';$('paSshDisconnectBtn').disabled=false;$('paSshSessionLabel').textContent=`${d.username}@${d.ip}:${d.port}`;$('paTerminalInput').disabled=false;$('paTerminalInput').focus();
  const proto=location.protocol==='https:'?'wss:':'ws:';phantomSshSocket=new WebSocket(`${proto}//${location.host}/api/phantom-access/ssh/terminal?token=${encodeURIComponent(phantomSshSession)}`);
  phantomSshSocket.onopen=()=>{sshSetState('CONNECTED','ok');$('paTerminalLatency').textContent='SSH SESSION ACTIVE';$('paTerminalInput').focus();sshResizeTerminal();if(window.ResizeObserver){phantomSshResizeObserver=new ResizeObserver(sshResizeTerminal);phantomSshResizeObserver.observe($('paTerminalOutput'));}};
  phantomSshSocket.onmessage=e=>{try{const m=JSON.parse(e.data);if(m.type==='output')sshAppend(m.data);else if(m.type==='status'&&m.state==='closed')sshSetState('CLOSED','warn');}catch(_){sshAppend(e.data);}};
  phantomSshSocket.onerror=()=>{sshSetState('CONNECTION ERROR','bad');};
  phantomSshSocket.onclose=()=>{if(phantomSshResizeObserver){phantomSshResizeObserver.disconnect();phantomSshResizeObserver=null;}sshSetState('DISCONNECTED','warn');$('paTerminalInput').disabled=true;$('paSshDisconnectBtn').disabled=true;$('paSshConnectBtn').disabled=false;$('paTerminalLatency').textContent='SESSION CLOSED';phantomSshSocket=null;phantomSshSession='';phantomSshSessionTarget='';};
 }catch(e){sshSetState('AUTH FAILED','bad');$('paTerminalOutput').textContent='SSH connection failed: '+e.message+'\n';$('paSshConnectBtn').disabled=false;$('paSshPassword').value='';$('paSshPassphrase').value='';}
}
function sshSend(data){if(phantomSshSocket&&phantomSshSocket.readyState===WebSocket.OPEN)phantomSshSocket.send(JSON.stringify({type:'input',data}));}
function sshResizeTerminal(){if(!phantomSshSocket||phantomSshSocket.readyState!==WebSocket.OPEN)return;const box=$('paTerminalOutput');const cols=Math.max(40,Math.min(240,Math.floor(box.clientWidth/8)));const rows=Math.max(10,Math.min(100,Math.floor(box.clientHeight/19)));phantomSshSocket.send(JSON.stringify({type:'resize',cols,rows}));}
function sshDisconnect(){if(phantomSshSocket){try{if(phantomSshSocket.readyState===WebSocket.OPEN)phantomSshSocket.send(JSON.stringify({type:'close'}));}catch(_){}try{phantomSshSocket.close();}catch(_){}}else if(phantomSshSession){sshApi('close',{session_token:phantomSshSession}).catch(()=>{});phantomSshSession='';phantomSshSessionTarget='';}}
function sshTerminalKeydown(e){
 if(!phantomSshSocket||phantomSshSocket.readyState!==WebSocket.OPEN)return;
 const map={Enter:'\r',Backspace:'\x7f',Tab:'\t',Escape:'\x1b',ArrowUp:'\x1b[A',ArrowDown:'\x1b[B',ArrowRight:'\x1b[C',ArrowLeft:'\x1b[D',Home:'\x1b[H',End:'\x1b[F',Delete:'\x1b[3~',PageUp:'\x1b[5~',PageDown:'\x1b[6~'};
 if(e.ctrlKey&&e.key.toLowerCase()==='c'){e.preventDefault();sshSend('\x03');return;}
 if(e.ctrlKey&&e.key.toLowerCase()==='d'){e.preventDefault();sshSend('\x04');return;}
 if(e.ctrlKey&&e.key.toLowerCase()==='l'){e.preventDefault();sshSend('\x0c');return;}
 if(e.ctrlKey&&e.key.toLowerCase()==='a'){e.preventDefault();sshSend('\x01');return;}
 if(e.ctrlKey&&e.key.toLowerCase()==='e'){e.preventDefault();sshSend('\x05');return;}
 if(e.ctrlKey&&e.key.toLowerCase()==='u'){e.preventDefault();sshSend('\x15');return;}
 if(e.ctrlKey&&e.key.toLowerCase()==='w'){e.preventDefault();sshSend('\x17');return;}
 if(map[e.key]){e.preventDefault();sshSend(map[e.key]);return;}
 if(e.key.length===1&&!e.altKey&&!e.metaKey){e.preventDefault();sshSend(e.key);}
}
function sshTerminalPaste(e){if(!phantomSshSocket||phantomSshSocket.readyState!==WebSocket.OPEN)return;const text=e.clipboardData?.getData('text');if(text){e.preventDefault();sshSend(text.replace(/\r?\n/g,'\r'));}}
function bindPhantomTerminal(){
 $('phantomAccessRows')?.addEventListener('change',e=>{if(e.target.matches('.pa-device-check'))updatePhantomSelectionCount();});
 $('phantomAccessRows')?.addEventListener('click',e=>{const b=e.target.closest('[data-pa-action]');if(!b)return;const ip=b.dataset.ip;const action=b.dataset.paAction;if(action==='probe')probePhantom(ip);else if(action==='select')selectPhantom(ip);else if(action==='terminal'){selectPhantom(ip);$('phantomTerminal').scrollIntoView({behavior:'smooth',block:'center'});$('paSshFingerprintBtn').focus();}});
 $('paSshFingerprintBtn')?.addEventListener('click',sshReviewHostKey);$('paSshTrustBtn')?.addEventListener('click',sshTrustHostKey);$('paSshConnectBtn')?.addEventListener('click',sshConnect);$('paSshDisconnectBtn')?.addEventListener('click',sshDisconnect);$('paSshAuth')?.addEventListener('change',sshAuthFields);$('paSshPort')?.addEventListener('change',()=>{phantomSshFingerprint='';phantomSshTrusted=false;phantomSshTrustedTarget='';$('paSshFingerprint').textContent='Port changed. Review the SSH host key again.';$('paSshTrustBtn').disabled=true;$('paSshConnectBtn').disabled=true;});$('paTerminalClear')?.addEventListener('click',()=>{phantomTerminalBuffer='';phantomTerminalCursor=0;phantomTerminalPendingCR=false;$('paTerminalOutput').textContent='';});$('paTerminalInput')?.addEventListener('keydown',sshTerminalKeydown);$('paTerminalInput')?.addEventListener('paste',sshTerminalPaste);sshAuthFields();
}
bindPhantomTerminal();

function bindCommandCenterEvents(){
 $('agentRows')?.addEventListener('click',e=>{const b=e.target.closest('[data-agent-action]');if(!b)return;const id=b.dataset.agentId;const action=b.dataset.agentAction;if(action==='restart_computer')restartRemote(id);else if(action==='shutdown_computer')shutdownRemote(id);else if(action==='restart_service')restartRemoteService(id);else if(action==='revoke')revokeAgent(id);else agentAction(id,action,{},action==='lock_workstation');});
 $('agentResultRows')?.addEventListener('click',e=>{const row=e.target.closest('[data-command-id]');if(row)showAgentResult(Number(row.dataset.commandId));});
 $('agentResultRows')?.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){const row=e.target.closest('[data-command-id]');if(row){e.preventDefault();showAgentResult(Number(row.dataset.commandId));}}});
}
bindCommandCenterEvents();

async function loadCommandCenter(){
 try{
  const [agents,summary,audit,results]=await Promise.all([fetch('/api/command/agents').then(r=>r.json()),fetch('/api/command/summary').then(r=>r.json()),fetch('/api/command/audit').then(r=>r.json()),fetch('/api/command/results').then(r=>r.json())]);
  $('agentManaged').textContent=summary.managed||0;$('agentOnline').textContent=summary.online||0;$('agentQueued').textContent=summary.queued_commands||0;$('agentHubState').textContent=summary.hub?.state||'UNKNOWN';
  $('agentRows').innerHTML=agents.map(a=>{
   const inv=a.inventory||{},cpu=inv.cpu_percent??'—',ram=inv.memory_percent??'—';
   const caps=new Set(Array.isArray(a.capabilities)?a.capabilities:[]);
   const id=esc(a.agent_id),buttons=[];
   if(a.status==='ONLINE'){
    if(caps.has('inventory'))buttons.push('<button class="secondary" data-agent-action="refresh_inventory" data-agent-id="'+id+'">Refresh</button>');
    if(caps.has('processes'))buttons.push('<button class="secondary" data-agent-action="list_processes" data-agent-id="'+id+'">Processes</button>');
    if(caps.has('services'))buttons.push('<button class="secondary" data-agent-action="list_services" data-agent-id="'+id+'">Services</button>');
    if(caps.has('lock'))buttons.push('<button class="secondary" data-agent-action="lock_workstation" data-agent-id="'+id+'">Lock</button>');
    if(caps.has('power-control'))buttons.push('<button class="secondary" data-agent-action="restart_computer" data-agent-id="'+id+'">Restart PC</button>','<button class="secondary" data-agent-action="shutdown_computer" data-agent-id="'+id+'">Shut down</button>');
    if(caps.has('services'))buttons.push('<button class="secondary" data-agent-action="restart_service" data-agent-id="'+id+'">Restart service</button>');
   }
   if(a.status!=='REVOKED')buttons.push('<button class="secondary" data-agent-action="revoke" data-agent-id="'+id+'">Revoke</button>');
   const capSummary=caps.has('inventory-report')?'Inventory reporting only':Array.from(caps).join(' · ');
   const controls=a.status==='REVOKED'?'Revoked':(buttons.join(' ')||'No supported controls');
   return '<tr><td><strong>'+esc(a.hostname)+'</strong><div class="hint mono">'+id+'</div><div class="hint">'+esc(capSummary||'No capabilities')+'</div></td><td>'+esc(a.platform)+'<div class="hint">'+esc(inv.manufacturer||'')+' '+esc(inv.model||'')+'</div><div class="hint">'+esc(a.os_version)+'</div></td><td><span class="pill '+(a.status==='REVOKED'?'bad':(a.status==='ONLINE'?'':'warn'))+'">'+esc(a.status)+'</span></td><td>'+esc(a.last_seen||'—')+'</td><td>'+esc(cpu)+(cpu==='—'?'':'%')+'</td><td>'+esc(ram)+(ram==='—'?'':'%')+'</td><td class="mono">'+esc(a.last_ip||'—')+'</td><td>'+controls+'</td></tr>';
  }).join('')||'<tr><td colspan="8">No endpoints enrolled. Generate a one-time enrolment token to begin.</td></tr>';
  $('agentAuditRows').innerHTML=audit.map(x=>`<tr><td>${esc(x.timestamp)}</td><td class="mono">${esc(x.agent_id)}</td><td>${esc(x.actor)}</td><td>${esc(x.action)}</td><td>${esc(x.outcome)}</td><td>${esc(x.details)}</td></tr>`).join('')||'<tr><td colspan="6">No audit records.</td></tr>';
  $('agentResultRows').innerHTML=results.map(x=>`<tr class="clickrow" tabindex="0" role="button" data-command-id="${Number(x.command_id)||0}"><td>#${Number(x.command_id)||0}</td><td>${esc(x.hostname)}</td><td>${esc(x.action)}</td><td>${esc(x.status)}</td><td>${esc(x.completed_at||'—')}</td></tr>`).join('')||'<tr><td colspan="5">No command results.</td></tr>';window.agentCommandResults=results;
 }catch(e){$('agentRows').innerHTML='<tr><td colspan="8">Command Centre unavailable: '+esc(e.message)+'</td></tr>';}
}
function showAgentResult(id){const item=(window.agentCommandResults||[]).find(x=>x.command_id===id);if(item)$('agentCommandOutput').textContent=JSON.stringify({command_id:item.command_id,device:item.hostname,action:item.action,status:item.status,result:item.result},null,2);}
async function createAgentToken(){
 if(!confirm('Generate a one-time enrolment token valid for 15 minutes?'))return;
 try{const r=await fetch('/api/command/enrol-token',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({confirm:true})});const d=await r.json();if(!r.ok)throw new Error(d.error||r.status);$('agentToken').textContent=d.token;$('agentTokenBox').style.display='block';await loadCommandCenter();}catch(e){alert('Could not create token: '+e.message);}
}
async function agentAction(id,action,args={},confirmation=false){
 const risky=['restart_computer','shutdown_computer','restart_service','lock_workstation'];
 if(risky.includes(action)&&!confirm(`Queue ${action.replaceAll('_',' ')} for ${id}? The action will be recorded in the audit log.`))return;
 try{const r=await fetch(`/api/command/agents/${encodeURIComponent(id)}/commands`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action,args,confirm:confirmation||risky.includes(action)})});const d=await r.json();if(!r.ok)throw new Error(d.error||r.status);alert(`Action queued. Command #${d.command_id}`);await loadCommandCenter();}catch(e){alert('Action not queued: '+e.message);}
}
async function restartRemote(id){if(!confirm('Restart '+id+'? The endpoint will schedule a restart in 60 seconds.'))return;await agentAction(id,'restart_computer',{},true);}
async function shutdownRemote(id){if(!confirm('Shut down '+id+'? The endpoint will schedule shutdown in 60 seconds.'))return;await agentAction(id,'shutdown_computer',{},true);}
async function restartRemoteService(id){const name=prompt('Exact Windows service name to restart (protected core services are blocked):');if(!name)return;if(!confirm('Restart Windows service '+name+' on '+id+'?'))return;await agentAction(id,'restart_service',{service_name:name},true);}
async function revokeAgent(id){if(!confirm(`Immediately revoke ${id}? Its future requests will be rejected and queued commands cancelled.`))return;try{const r=await fetch(`/api/command/agents/${encodeURIComponent(id)}/revoke`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({confirm:true})});const d=await r.json();if(!r.ok)throw new Error(d.error||r.status);await loadCommandCenter();}catch(e){alert(e.message);}}

loadCommandCenter();setInterval(loadCommandCenter,10000);loadPhantomAccess();setInterval(loadPhantomAccess,30000);

/* NETWORK CONTROL ENGINE — router-mediated controls with explicit confirmation. */
let ncStatusInFlight=false;let ncLastStatusAt=0;
function renderNetworkControlDeviceOptions(devices){const select=$("ncDeviceSelect");if(!select)return;const current=select.value;const online=(Array.isArray(devices)?devices:[]).filter(x=>String(x.status||"").toUpperCase()==="ONLINE"&&x.ip);const options=online.map(x=>{const label=[x.hostname||x.device_name||x.device_type||"Unknown device",x.ip].filter(Boolean).join(" · ");return '<option value="'+esc(x.ip)+'">'+esc(label)+'</option>';}).join("");select.innerHTML='<option value="">Select an online device…</option>'+options;if(online.some(x=>x.ip===current))select.value=current;}
function ncOutput(value,isError){const box=$("ncControlOutput");if(box)box.textContent=typeof value==="string"?value:JSON.stringify(value,null,2);if(isError&&$("ncRouterStatus"))$("ncRouterStatus").textContent=String(value);}
async function ncPost(path,payload){const response=await fetch(path,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)});let data={};try{data=await response.json();}catch(_){}if(!response.ok){const error=new Error(data.error||("HTTP "+response.status));error.payload=data;error.status=response.status;throw error;}return data;}
async function discoverNetworkRouter(){const panel=$("ncRouterDiscovery");if(panel)panel.textContent="Identifying the active gateway using bounded read-only probes…";try{const data=await getJSON("/api/network-control/discover",9000);if(panel){const lines=["ROUTER: "+(data.vendor||"Unknown"),"GATEWAY: "+(data.host||"—"),"IDENTIFICATION: "+(data.status||"—")+" · confidence "+(data.confidence||"—"),"MODEL: "+(data.model||"Not established from available evidence"),"FIRMWARE: "+(data.firmware||"Not established"),"MANAGEMENT PORTS: "+((data.open_management_ports||[]).join(", ")||"No standard web port responded"),"CONTROL ADAPTERS: "+((data.control_adapter_candidates||[]).join("; ")||"No verified adapter candidate yet"),data.control_message||"", "Credentials sent: NO · Configuration changed: NO"];panel.textContent=lines.join("\\n");}if($("ncRouterHost")&&data.host)$("ncRouterHost").value=data.host;if($("ncRouterPort")&&data.open_management_ports?.length)$("ncRouterPort").value=data.open_management_ports.includes(443)?443:data.open_management_ports[0];ncOutput(data);}catch(error){if(panel)panel.textContent=error.message;ncOutput(error.message,true);}}
async function connectNetworkRouter(){const host=$("ncRouterHost")?.value.trim()||"",username=$("ncRouterUser")?.value.trim()||"",password=$("ncRouterPassword")?.value||"",port=Number($("ncRouterPort")?.value||443),ca_file=$("ncRouterCA")?.value.trim()||"";if(!host||!username||!password){ncOutput("Enter the router IPv4 address, dedicated REST username and password.",true);return;}if(!confirm("Connect to this router using verified HTTPS and perform read-only capability checks?"))return;if($("ncRouterStatus"))$("ncRouterStatus").textContent="Testing verified HTTPS connection…";try{const result=await ncPost("/api/network-control/connect",{provider:"mikrotik-routeros",host,username,password,port,ca_file,confirm:true});$("ncRouterPassword").value="";ncOutput(result);await loadNetworkControlStatus(true);}catch(error){ncOutput(error.message,true);}}
async function disconnectNetworkRouter(){try{const result=await ncPost("/api/network-control/disconnect",{confirm:true});ncOutput(result);await loadNetworkControlStatus(true);}catch(error){ncOutput(error.message,true);}}
function ncSelectedIP(){return $("ncDeviceSelect")?.value||"";}
async function applyNetworkBandwidth(){const ip=ncSelectedIP(),download_mbps=Number($("ncDownloadLimit")?.value),upload_mbps=Number($("ncUploadLimit")?.value);if(!ip){ncOutput("Select an online device first.",true);return;}if(!confirm("Apply a router-enforced bandwidth limit to "+ip+"? Upload: "+upload_mbps+" Mbps. Download: "+download_mbps+" Mbps."))return;try{const result=await ncPost("/api/network-control/bandwidth",{ip,download_mbps,upload_mbps,confirm:true});ncOutput(result);await loadNetworkControlStatus(true);}catch(error){ncOutput(error.message,true);}}
async function removeNetworkBandwidth(){const ip=ncSelectedIP();if(!ip){ncOutput("Select a device first.",true);return;}if(!confirm("Remove only the NetworkRadar-managed bandwidth queue for "+ip+"?"))return;try{const result=await ncPost("/api/network-control/bandwidth/remove",{ip,confirm:true});ncOutput(result);await loadNetworkControlStatus(true);}catch(error){ncOutput(error.message,true);}}
async function ncPause(path,payload){try{let result;try{result=await ncPost(path,Object.assign({},payload,{allow_ipv4_only:false,confirm:true}));}catch(error){if(!error.payload?.requires_ipv4_only_confirmation)throw error;if(!confirm(error.message+"\n\nContinue with an explicitly IPv4-only restriction? IPv6 internet access may remain available."))return;result=await ncPost(path,Object.assign({},payload,{allow_ipv4_only:true,confirm:true}));}ncOutput(result);await loadNetworkControlStatus(true);}catch(error){ncOutput(error.message,true);}}
function getPauseDuration(scope){const valueEl=$(scope==="network"?"ncNetworkDurationValue":"ncDeviceDurationValue");const unitEl=$(scope==="network"?"ncNetworkDurationUnit":"ncDeviceDurationUnit");const raw=String(valueEl?.value??"").trim();if(!/^\d+$/.test(raw)){throw new Error("Enter a whole-number pause duration.");}const value=Number(raw),unit=Number(unitEl?.value||1),minutes=value*unit;if(!Number.isSafeInteger(minutes)||minutes<1||minutes>1440){throw new Error("Choose a duration between 1 minute and 24 hours.");}return minutes;}
function setPausePreset(scope,minutes){const valueEl=$(scope==="network"?"ncNetworkDurationValue":"ncDeviceDurationValue");const unitEl=$(scope==="network"?"ncNetworkDurationUnit":"ncDeviceDurationUnit");if(!valueEl||!unitEl)return;if(minutes%60===0){valueEl.value=String(minutes/60);unitEl.value="60";}else{valueEl.value=String(minutes);unitEl.value="1";}}
function describePauseDuration(minutes){if(minutes%1440===0)return (minutes/1440)+" day"+(minutes===1440?"":"s");if(minutes%60===0)return (minutes/60)+" hour"+(minutes===60?"":"s");return minutes+" minute"+(minutes===1?"":"s");}
function pauseExpiryText(minutes){return new Date(Date.now()+minutes*60000).toLocaleString(undefined,{dateStyle:"medium",timeStyle:"short"});}
async function pauseNetworkDevice(){const ip=ncSelectedIP();if(!ip){ncOutput("Select an online device first.",true);return;}let minutes;try{minutes=getPauseDuration("device");}catch(error){ncOutput(error.message,true);return;}if(!confirm("Temporarily pause internet access for "+ip+" for "+describePauseDuration(minutes)+"?\n\nExpected automatic restoration: "+pauseExpiryText(minutes)+".\nThe router enforces this timer even if NetworkRadar closes."))return;await ncPause("/api/network-control/pause",{scope:"device",ip,duration_minutes:minutes});}
async function pauseWholeNetwork(){let minutes;try{minutes=getPauseDuration("network");}catch(error){ncOutput(error.message,true);return;}if(!confirm("PAUSE INTERNET FOR THE ENTIRE CURRENT AUTHORISED NETWORK for "+describePauseDuration(minutes)+"?\n\nExpected automatic restoration: "+pauseExpiryText(minutes)+".\nLocal LAN traffic and router management are not targeted. The router enforces the timer even if NetworkRadar closes."))return;await ncPause("/api/network-control/pause",{scope:"network",duration_minutes:minutes});}
async function resumeNetworkDevice(){const ip=ncSelectedIP();if(!ip){ncOutput("Select a device first.",true);return;}if(!confirm("Remove NetworkRadar-managed pause entries for "+ip+"?"))return;try{const result=await ncPost("/api/network-control/resume",{scope:"device",ip,confirm:true});ncOutput(result);await loadNetworkControlStatus(true);}catch(error){ncOutput(error.message,true);}}
async function resumeWholeNetwork(){if(!confirm("Resume internet access by removing NetworkRadar-managed network pause entries?"))return;try{const result=await ncPost("/api/network-control/resume",{scope:"network",confirm:true});ncOutput(result);await loadNetworkControlStatus(true);}catch(error){ncOutput(error.message,true);}}
async function restoreNetworkControl(){if(!confirm("EMERGENCY RESTORE: remove only NetworkRadar-managed pause entries, bandwidth queues and firewall rules from the connected router? Other router rules will be left untouched."))return;try{const result=await ncPost("/api/network-control/restore",{confirm:true});ncOutput(result);await loadNetworkControlStatus(true);}catch(error){ncOutput(error.message,true);}}
function renderNetworkControlStatus(data){const badge=$("ncConnectionBadge"),status=$("ncRouterStatus");if(!data?.connected){if(badge){badge.textContent="DISCONNECTED";badge.className="pill warn";}if(status)status.textContent=data?.message||"No router connected. Router controls are inactive.";$("ncRouterIdentity").textContent="—";$("ncRouterModel").textContent="—";$("ncRouterIPv6").textContent="UNKNOWN";$("ncRouterFastTrack").textContent="UNKNOWN";$("ncActivePolicies").textContent="No active router policies loaded.";return;}if(badge){badge.textContent="ROUTER CONNECTED";badge.className="pill ok";}if(status)status.textContent="Connected to "+(data.identity||data.host)+" · "+data.host+" · HTTPS REST · credentials memory-only.";$("ncRouterIdentity").textContent=data.identity||data.host||"—";$("ncRouterModel").textContent=[data.model,data.version].filter(Boolean).join(" · ")||"—";$("ncRouterIPv6").textContent=data.ipv6_supported?"AVAILABLE":"NOT VERIFIED";$("ncRouterFastTrack").textContent=data.fasttrack_detected?("DETECTED · "+(data.fasttrack_rule_count||1)+" RULE(S) · LIMIT BLOCKED"):"NOT DETECTED";const lines=[];(data.active_ipv4_pauses||[]).forEach(x=>lines.push("IPv4 pause · "+(x.address||"—")+" · "+(x.timeout||"timer managed by router")));(data.active_ipv6_pauses||[]).forEach(x=>lines.push("IPv6 pause · "+(x.address||"—")+" · "+(x.timeout||"timer managed by router")));if(data.bandwidth_enforcement_status==="BLOCKED_BY_FASTTRACK")lines.push("ENFORCEMENT BLOCKED · FastTrack can bypass Simple Queues. Remove the affected traffic from FastTrack before applying a speed cap.");(data.bandwidth_queues||[]).forEach(x=>lines.push("Bandwidth · "+(x.target||"—")+" · "+(x.max_limit||"—")+" · rate "+(x.rate||"not reported")+" · bytes "+(x.bytes||"not reported")));$("ncActivePolicies").textContent=lines.join("\n")||"No active NetworkRadar-managed router policies.";}
async function loadNetworkControlStatus(force){if(ncStatusInFlight||(!force&&Date.now()-ncLastStatusAt<15000))return;ncStatusInFlight=true;ncLastStatusAt=Date.now();try{const data=await getJSON("/api/network-control/status",12000);renderNetworkControlStatus(data);}catch(error){const status=$("ncRouterStatus");if(status)status.textContent="Router status unavailable: "+error.message;}finally{ncStatusInFlight=false;}}
