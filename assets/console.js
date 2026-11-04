'use strict';
const byId = id => document.getElementById(id);
const token = document.querySelector('meta[name="console-token"]').content;
let scanId = null, timer = null;
async function request(path, body) {
  const response = await fetch(path, body === undefined ? {} : {
    method:'POST', headers:{'Content-Type':'application/json','X-Console-Token':token}, body:JSON.stringify(body)
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || 'Request failed');
  return data;
}
function element(tag, text, className) {
  const node = document.createElement(tag); node.textContent = String(text ?? '');
  if (className) node.className = className;
  return node;
}
function render(data) {
  byId('result').hidden = false;
  byId('status').textContent = {running:'Assessment running',completed:'Assessment complete',partial:'Partial assessment · review gaps',failed:'Assessment could not complete',stopped:'Assessment stopped'}[data.status] || data.status;
  byId('target').textContent = data.url;
  byId('elapsed').textContent = `${Math.floor(data.elapsed/60)}m ${data.elapsed%60}s`;
  byId('log').textContent = data.log || 'Preparing scanner…';
  const stats = data.statistics || {};
  byId('candidates').textContent = stats.vulnerability_candidates ?? '—';
  byId('configuration').textContent = stats.configuration_findings ?? '—';
  const coverage = data.coverage || [];
  byId('completed').textContent = data.coverage ? coverage.filter(x=>x.status.startsWith('completed')).length : '—';
  byId('coverage').replaceChildren(...coverage.map(row=>{
    const tr = document.createElement('tr');
    for (const text of [row.tool, row.status, row.reason]) tr.append(element('td',text));
    return tr;
  }));
  if (data.findings) byId('findings').replaceChildren(...(data.findings.length ? data.findings.map(row=>{
    const div = element('article','','finding');
    div.append(element('span',`${row.severity} · ${row.category}`,'severity'),element('p',row.title),element('p',`${row.validation_status} · ${row.url}`,'muted'));
    return div;
  }) : [element('p','No findings recorded. Review coverage before drawing conclusions.','muted')]));
  byId('report').hidden = !data.report;
  if (data.report) byId('report').href = `/report/${data.id}`;
  byId('stop').hidden = data.status !== 'running';
  byId('start').disabled = data.status === 'running';
}
async function poll() {
  try {
    const data = await request(`/api/scans/${scanId}`); render(data);
    if (data.status === 'running') timer = setTimeout(poll,1500);
    else sessionStorage.removeItem('twiy-scan');
  } catch(error) { byId('error').textContent = error.message + ' · Reload to reconnect.'; }
}
byId('scan-form').addEventListener('submit',async event=>{
  event.preventDefault(); byId('error').textContent = ''; byId('start').disabled = true;
  try {
    clearTimeout(timer);
    const result = await request('/api/scans',{url:byId('url').value.trim()});
    scanId = result.id; sessionStorage.setItem('twiy-scan',scanId); await poll();
  } catch(error) { byId('error').textContent = error.message; byId('start').disabled = false; }
});
byId('stop').addEventListener('click',async()=>{
  try { await request(`/api/scans/${scanId}/stop`,{}); byId('stop').textContent='Stopping…'; }
  catch(error) { byId('error').textContent=error.message; }
});
scanId=sessionStorage.getItem('twiy-scan'); if(scanId) poll();
