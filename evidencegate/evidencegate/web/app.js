"use strict";
const state={provenance:null,sbom:null,scan:null,policy:null};
const $=id=>document.getElementById(id);
let lastReport=null;
function showError(message){$("error").textContent=message;$("error").hidden=!message;}
function invalidate(){lastReport=null;$("results").hidden=true;}
function setName(name,text){$(name+"-name").textContent=text;$(name+"-name").classList.toggle("loaded",Boolean(state[name]));}
for(const name of Object.keys(state)){
  $(name+"-file").addEventListener("change",async event=>{
    invalidate();showError("");$("demo-badge").hidden=true;
    const file=event.target.files[0];state[name]=null;setName(name,"No file selected");
    if(!file)return;
    if(file.size>8*1024*1024){showError("Each JSON file must be smaller than 8 MiB.");return;}
    state[name]=await file.text();setName(name,file.name);
  });
}
$("artifact-file").addEventListener("change",async event=>{
  invalidate();showError("");$("demo-badge").hidden=true;
  const file=event.target.files[0];if(!file)return;
  if(file.size>128*1024*1024){showError("Use the CLI to hash artifacts larger than 128 MiB.");return;}
  try{
    const hash=await crypto.subtle.digest("SHA-256",await file.arrayBuffer());
    $("digest").value=Array.from(new Uint8Array(hash),b=>b.toString(16).padStart(2,"0")).join("");
    $("artifact-note").textContent="Hashed exact file bytes: "+file.name+". This is not an OCI manifest or image configuration digest.";
  }catch(error){showError("Could not hash this file. Use the CLI or provide its independently calculated SHA-256.");}
});
$("digest").addEventListener("input",invalidate);
$("load-demo").addEventListener("click",async()=>{
  invalidate();showError("");
  try{
    const response=await fetch("/api/demo");if(!response.ok)throw new Error("Could not load the example.");
    const data=await response.json();
    if($("scenario").value==="mismatch")data.scan.subject.sha256="0".repeat(64);
    if($("scenario").value==="stale")data.scan.scanned_at=new Date(Date.now()-73*3600000).toISOString();
    if($("scenario").value==="vulnerable")data.scan.vulnerabilities=[{id:"SYNTHETIC-001",package:"example-package",severity:"HIGH"}];
    $("digest").value=data.artifact_sha256;
    for(const name of Object.keys(state)){state[name]=data[name];setName(name,"synthetic-"+name+".json");$(name+"-file").value="";}
    $("artifact-file").value="";$("demo-badge").hidden=false;
    $("artifact-note").textContent="Synthetic example only. No software was built or scanned; timestamps were generated for this demonstration.";
  }catch(error){showError(error.message);}
});
function renderRows(){
  const target=$("findings");target.replaceChildren();
  if(!lastReport)return;
  for(const check of lastReport.checks){
    if($("failed-only").checked&&check.status!=="fail")continue;
    const row=document.createElement("tr");
    const code=document.createElement("td");code.textContent=check.id;
    const status=document.createElement("td");status.textContent=check.status.toUpperCase();status.className="status-"+check.status;
    const message=document.createElement("td");message.textContent=check.message;
    const action=document.createElement("small");action.textContent=check.action;message.append(action);
    row.append(code,status,message);target.append(row);
  }
}
$("check-form").addEventListener("submit",async event=>{
  event.preventDefault();showError("");invalidate();$("run-check").disabled=true;
  try{
    const response=await fetch("/api/check",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({artifact_sha256:$("digest").value.trim(),...state})});
    const report=await response.json();if(!response.ok)throw new Error(report.error||"Assessment failed.");
    lastReport=report;$("decision").textContent=report.decision;$("decision").classList.toggle("block",report.decision==="BLOCK");
    $("result-title").textContent=report.decision==="BLOCK"?"Evidence needs attention":"Supplied evidence meets policy";
    $("result-summary").textContent=`${report.summary.passed} of ${report.summary.total} checks passed · ${report.summary.failed} failed · ${new Date(report.assessed_at).toLocaleString()}`;
    renderRows();$("results").hidden=false;$("results").scrollIntoView({behavior:"smooth",block:"start"});
  }catch(error){showError(error.message);}finally{$("run-check").disabled=false;}
});
$("failed-only").addEventListener("change",renderRows);
function saveFile(content,type,name){const url=URL.createObjectURL(new Blob([content],{type}));const a=document.createElement("a");a.href=url;a.download=name;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);}
$("download-json").addEventListener("click",()=>{if(lastReport)saveFile(JSON.stringify(lastReport,null,2),"application/json","evidencegate-report.json");});
function csvCell(value){let text=String(value);if(/^[\s]*[=+@\-\t\r]/.test(text))text="'"+text;return '"'+text.replaceAll('"','""')+'"';}
$("download-csv").addEventListener("click",()=>{
  if(!lastReport)return;const fields=["id","category","status","message","action"];
  saveFile([fields.map(csvCell).join(","),...lastReport.checks.map(c=>fields.map(k=>csvCell(c[k])).join(","))].join("\r\n"),"text/csv","evidencegate-findings.csv");
});
