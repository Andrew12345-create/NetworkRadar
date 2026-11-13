const $=id=>document.getElementById(id);
// Startup diagnostics: make a failed dashboard script/API visible instead of leaving skeletons.
try{const c=$("connection");if(c){c.textContent="SCRIPT ACTIVE";c.className="pill warn";}}catch(_e){}
window.addEventListener("error",e=>{try{const c=$("connection");if(c){c.textContent="SCRIPT ERROR";c.className="pill bad";}const u=$("updated");if(u)u.textContent="Dashboard error: "+(e.message||"unknown script error");}catch(_x){}});
window.addEventListener("unhandledrejection",e=>{try{const u=$("updated");if(u)u.textContent="Dashboard request error: "+String(e.reason?.message||e.reason||"unknown");}catch(_x){}});
function esc(v){return String(v??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
async function getJSON(p){const ctl=new AbortController();const timer=setTimeout(()=>ctl.abort(),10000);try{const r=await fetch(p,{cache:"no-store",signal:ctl.signal});if(!r.ok)throw new Error("HTTP "+r.status);return await r.json();}finally{clearTimeout(timer);}}
function pill(el,text,state){el.textContent=text;el.className="pill"+(state==="bad"?" bad":state==="warn"?" warn":"");}
function toast(m){const t=$("toast");t.textContent=m;t.style.display="block";setTimeout(()=>t.style.display="none",3500);}
let deviceCache=[];
function filterDevices(){
 const q=($("deviceSearch")?.value||"").toLowerCase().trim();
 const st=$("deviceFilter")?.value||"ALL";
 const rows=deviceCache.filter(x=>{
  const b=[x.ip,x.device_name,x.manual_name,x.device_type,x.manufacturer,x.mac,x.hostname,x.model].join(" ").toLowerCase();
  const ok=st==="ALL"||(st==="ONLINE"&&x.status==="ONLINE")||(st==="OFFLINE"&&x.status==="OFFLINE")||(st==="TRUSTED"&&x.trust_state==="TRUSTED");
  return ok&&(!q||b.includes(q));
 });
 $("deviceRows").innerHTML=rows.map(x=>`<tr class="clickrow" data-open-device="${esc(x.ip)}" tabindex="0" role="button"><td class="mono">${esc(x.ip)}</td><td>${esc(x.manual_name||x.device_name)}</td><td>${esc(x.device_type)}</td><td>${esc(x.manufacturer)}</td><td>${esc(x.identification_confidence)}%</td><td class="risk-${esc(x.risk_band||"UNKNOWN")}">${esc(x.risk_band||"UNKNOWN")}</td><td class="${x.status==="ONLINE"?"green":"muted"}">${esc(x.status)}</td></tr>`).join("")||'<tr><td colspan="7">No matches.</td></tr>';
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
  identity+='<h3>WHY NETWORKRADAR THINKS THIS IS THIS DEVICE</h3>';
  identity+=deviceRows(ass,[['ATTRIBUTE','attribute'],['ASSESSED VALUE','value'],['CONFIDENCE','confidence'],['STATUS','status'],['EVIDENCE COUNT','evidence_count'],['INDEPENDENT SOURCES','independent_sources'],['RATIONALE','rationale']],'No persisted attribute assessments yet.');
  identity+='<h3>RAW IDENTITY EVIDENCE</h3>'+deviceRows(ev,[['TIME','timestamp'],['SOURCE','source'],['ATTRIBUTE','attribute'],['OBSERVED VALUE','value'],['CONFIDENCE','confidence'],['CLASS','class']]);
  if(rec.category){identity+=`<div class="notice"><b>${esc(rec.category)}</b> · ${esc(rec.confidence||0)}% · ${esc(rec.status||'UNKNOWN')}</div>`;identity+=deviceRows(rec.matches||[],[['MATCH','matched'],['CLASSIFICATION','category'],['SOURCE FAMILY','source_family'],['WEIGHT','weight']],'No signature matches.');}
  const oui=rec.nic_address_block_registrant||{};
   const hardware=deviceProfileCards([["DEVICE-REPORTED MANUFACTURER",d.reported_manufacturer||"Not observed"],["IEEE ADDRESS-BLOCK REGISTRANT",oui.organization||d.oui_manufacturer||"Not found"],["IEEE REGISTRY",oui.registry||"Unknown"],["ASSIGNED PREFIX",oui.prefix||"—"],["PREFIX LENGTH",oui.prefix_bits?oui.prefix_bits+" bits":"—"],["NMAP MAC VENDOR",d.manufacturer],["REPORTED MODEL",d.model],["HOSTNAME",d.hostname],["DEVICE CATEGORY",d.device_type],["MAC ADDRESS",d.mac],["MAC IDENTITY BASIS",d.identity_basis]]);
   if(oui.interpretation) hardware+='<div class="notice">'+esc(oui.interpretation)+'. The registrant may be an adapter supplier, OEM, ODM or another assignee; it is not automatically the device maker.</div>';
  const os=deviceProfileCards([["OS GUESS",d.os_guess],["OS FINGERPRINT CONFIDENCE",d.identification_confidence+"%"],["PASSIVE TCP HINT",rec.passive_tcp_os_hint],["RECOGNITION STATUS",rec.status],["ALTERNATIVE CLASSIFICATIONS",(rec.alternatives||[]).map(x=>x.category+" ("+x.confidence+"%)").join(" · ")],["LIMITATIONS",(rec.limitations||[]).join(" ")]]);
  const network=deviceProfileCards([["CURRENT IP",d.ip],["CURRENT MAC",d.mac],["IDENTITY KEY",d.device_id],["IDENTITY BASIS",d.identity_basis],["DHCP OBSERVATIONS",(p.dhcp_history||[]).length],["DNS OBSERVATIONS",(p.dns_activity||[]).length]]);
  let networkHtml=network+'<h3>DHCP HISTORY</h3>'+deviceRows(p.dhcp_history,[['TIME','timestamp'],['MESSAGE','message'],['HOSTNAME','hostname'],['VENDOR CLASS','vendor_class'],['CLIENT MAC','mac'],['SERVER','server_ip']]);
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
 try{await fetch("/api/scan",{method:"POST"});$("updated").textContent="Queued...";}
 catch(e){$("updated").textContent=e.message;}
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
let refreshInFlight=false;
async function refreshAll(){
 if(refreshInFlight)return;refreshInFlight=true;
 const specs=[
  ["status","/api/status"],["devices","/api/devices"],["domains","/api/domains"],
  ["alerts","/api/alerts"],["events","/api/events"],["dns","/api/dns"],
  ["progress","/api/progress"],["investigations","/api/investigations"],
  ["network","/api/network"],["diagnostics","/api/diagnostics"],
  ["engine","/api/engine_diagnostics"]
 ];
 try{
  const settled=await Promise.allSettled(specs.map(([,path])=>getJSON(path)));
  const data={},failed=[];
  settled.forEach((r,i)=>{const name=specs[i][0];if(r.status==="fulfilled")data[name]=r.value;else{data[name]=null;failed.push(name+": "+String(r.reason?.message||r.reason||"request failed"));}});
  const s=data.status||{},d=Array.isArray(data.devices)?data.devices:[],domains=Array.isArray(data.domains)?data.domains:[],a=Array.isArray(data.alerts)?data.alerts:[],e=Array.isArray(data.events)?data.events:[],inv=Array.isArray(data.investigations)?data.investigations:[],n=data.network||{},diag=data.diagnostics||{},eng=data.engine||{},j=data.progress||{};
  const statusOK=!!data.status;
  pill($("connection"),!statusOK?"API DEGRADED":(failed.length?"CONNECTED · PARTIAL":"CONNECTED"),!statusOK?"bad":(failed.length?"warn":"ok"));
  if(!statusOK){$("updated").textContent="Status API unavailable. "+failed.join(" | ");}
  else{$("updated").textContent="Updated "+(s.timestamp||new Date().toLocaleTimeString())+(failed.length?" · "+failed.length+" API request(s) failed: "+failed.map(x=>x.split(":")[0]).join(", "):"");}
  $("network").textContent=s.network||n.network||"—";$("activeSubnet").textContent=n.network||s.network||"—";
  $("defaultGateway").textContent=n.gateway||"—";$("fingerprint").textContent=n.fingerprint||"—";$("fpConf").textContent=(n.confidence||0)+"%";
  $("networkWarning").textContent=n.warning||(n.authorized?"Authorised.":"Passive only.");$("authorizeNetwork").style.display=n.authorized?"none":"inline-block";$("netAuthz").textContent=n.auth_decision||"—";
  $("jobPhase").textContent=j.phase||"—";$("jobMessage").textContent=j.message||"Waiting for engine status.";$("jobPercent").textContent=(j.percent??0)+"%";$("jobBar").style.width=(j.percent??0)+"%";
  $("online").textContent=s.online??"—";$("historical").textContent=s.historical??"—";$("deviceHint").textContent=(s.offline??"—")+" offline";$("openInvestigations").textContent=s.open_investigations??inv.length;
  const nr=$("networkRisk");nr.textContent=s.network_risk_band||"UNKNOWN";nr.className="value risk-"+(s.network_risk_band||"UNKNOWN");
  pill($("dnsStatus"),s.dns_status||"UNKNOWN",s.dns_status==="ONLINE"?"ok":"warn");pill($("dhcpStatus"),s.dhcp_status||"UNKNOWN",s.dhcp_status==="ONLINE"?"ok":"warn");pill($("arpStatus"),s.arp_status||"UNKNOWN",s.arp_status==="ONLINE"?"ok":"warn");
  const dhcp=eng.engines?.dhcp||{};$("dhcpClass").textContent=(dhcp.state||"UNKNOWN")+" — "+(dhcp.reason||"").slice(0,60);
  $("dbQueue").textContent=(s.db_health?.queued??"—")+" queued, "+(s.db_health?.processed??"—")+" done";$("scanQuality").textContent=(diag.scan_quality?.score??"—")+"/100 · "+(diag.scan_quality?.band||"—");
  if(data.devices){deviceCache=d;filterDevices();}else{$("deviceRows").innerHTML='<tr><td colspan="7">Device API unavailable. Check server log and /api/devices.</td></tr>';}
  $("domainRows").innerHTML=domains.map(x=>`<tr><td class="mono">${esc(x.domain)}</td><td>${x.query_count}</td><td>${esc(x.risk_level)}</td></tr>`).join("")||'<tr><td colspan="3">—</td></tr>';
  $("alertRows").innerHTML=a.map(x=>`<tr><td>${esc(x.timestamp)}</td><td class="mono">${esc(x.client_ip)}</td><td>${esc(x.rule_id)}</td><td class="${x.severity==="HIGH"?"red":"amber"}">${esc(x.severity)}</td></tr>`).join("")||'<tr><td colspan="4">—</td></tr>';
  $("eventRows").innerHTML=e.map(x=>`<tr><td>${esc(x.timestamp)}</td><td class="mono">${esc(x.ip)}</td><td>${esc(x.category)}</td><td>${esc(x.event_type)}</td><td>${esc(x.details)}</td></tr>`).join("")||'<tr><td colspan="5">—</td></tr>';
  $("behaviourStatus").textContent=diag.behaviour?.message||"Behaviour diagnostics unavailable.";
  $("behaviourRows").innerHTML=((diag.behaviour?.baseline_devices||0)>0?'<tr><td colspan="5">See device detail for samples.</td></tr>':'<tr><td colspan="5">Collecting baselines.</td></tr>');
  $("investigationRows").innerHTML=inv.map(x=>`<tr><td>${esc(x.timestamp)}</td><td>${esc(x.title)}</td><td>${esc(x.severity)}</td><td>${esc(x.status)}</td><td>${esc(x.evidence_count)}</td></tr>`).join("")||'<tr><td colspan="5">None.</td></tr>';
  loadProfiles();loadChanges();loadConfig();loadAlertStream();loadIdentityIntel();loadContinuity();loadCandidates();loadPhantomPanels();
 }catch(err){pill($("connection"),"DASHBOARD ERROR","bad");$("updated").textContent=err.message||String(err);}
 finally{refreshInFlight=false;}
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
  const [u,v,x]=await Promise.all([fetch('/api/unknown-hunter').then(r=>r.json()),fetch('/api/ipv6').then(r=>r.json()),fetch('/api/exposure').then(r=>r.json())]);
  $('unknownRows').innerHTML=u.map(d=>`<tr><td class="mono">${esc(d.ip)}</td><td>${esc(d.name)}</td><td>${esc(d.device_type)}</td><td>${esc(d.os_guess)}</td><td>${d.confidence}%</td><td>${d.evidence_count} / ${d.independent_sources} sources</td><td>${esc(d.status)}</td></tr>`).join('')||'<tr><td colspan="7">No low-confidence devices in current inventory.</td></tr>';
  $('ipv6Rows').innerHTML=v.map(d=>`<tr><td class="mono">${esc(d.ipv6)}</td><td class="mono">${esc(d.mac||'—')}</td><td>${esc(d.interface_alias||'—')}</td><td>${esc(d.state)}</td><td>${esc(d.timestamp)}</td><td>${esc(d.linked_device_id||'Uncorrelated')}</td></tr>`).join('')||'<tr><td colspan="6">No IPv6 neighbour observations recorded.</td></tr>';
  $('exposureRows').innerHTML=x.map(d=>`<tr><td class="mono">${esc(d.ip)}</td><td>${esc(d.title)}</td><td class="${d.severity==='HIGH'?'red':'amber'}">${esc(d.severity)}</td><td>${esc(d.observed_ports)}</td><td>${esc(d.recommendation)}</td><td>${esc(d.last_seen)}</td><td>${esc(d.status)}</td></tr>`).join('')||'<tr><td colspan="7">No current or stale exposure observations.</td></tr>';
 }catch(e){$('unknownRows').innerHTML='<tr><td colspan="7">Panel unavailable: '+esc(e.message)+'</td></tr>';}
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
  $('agentRows').innerHTML=agents.map(a=>{const inv=a.inventory||{};const cpu=inv.cpu_percent??'—';const ram=inv.memory_percent??'—';const id=esc(a.agent_id);const controls=a.status==='REVOKED'?'Revoked':`<button class="secondary" data-agent-action="refresh_inventory" data-agent-id="${id}">Refresh</button> <button class="secondary" data-agent-action="list_processes" data-agent-id="${id}">Processes</button> <button class="secondary" data-agent-action="list_services" data-agent-id="${id}">Services</button> <button class="secondary" data-agent-action="lock_workstation" data-agent-id="${id}">Lock</button> <button class="secondary" data-agent-action="restart_computer" data-agent-id="${id}">Restart PC</button> <button class="secondary" data-agent-action="shutdown_computer" data-agent-id="${id}">Shut down</button> <button class="secondary" data-agent-action="restart_service" data-agent-id="${id}">Restart service</button> <button class="secondary" data-agent-action="revoke" data-agent-id="${id}">Revoke</button>`;return `<tr><td><strong>${esc(a.hostname)}</strong><div class="hint mono">${id}</div></td><td>${esc(a.platform)}<div class="hint">${esc(a.inventory?.manufacturer||'')} ${esc(a.inventory?.model||'')}</div><div class="hint">${esc(a.os_version)}</div></td><td><span class="pill ${a.status==='REVOKED'?'bad':(a.status==='ONLINE'?'':'warn')}">${esc(a.status)}</span></td><td>${esc(a.last_seen||'—')}</td><td>${esc(cpu)}${cpu==='—'?'':'%'}</td><td>${esc(ram)}${ram==='—'?'':'%'}</td><td class="mono">${esc(a.last_ip||'—')}</td><td>${controls}</td></tr>`}).join('')||'<tr><td colspan="8">No endpoints enrolled. Generate a one-time enrolment token to begin.</td></tr>';
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
