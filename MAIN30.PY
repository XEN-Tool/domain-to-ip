# domain-to-ip.py
# Requirements:
# pip install flask requests pythonping dnspython playwright
# python -m playwright install chromium

from flask import Flask, request, jsonify, render_template_string
import re, requests, socket, platform
from pythonping import ping
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache

# Playwright optional
try:
    from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
    HAS_PLAYWRIGHT = True
except Exception:
    HAS_PLAYWRIGHT = False

# dnspython optional
try:
    import dns.resolver
    HAS_DNSPYTHON = True
except Exception:
    HAS_DNSPYTHON = False

app = Flask(__name__)

IPV4_RE = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})\b')
IPV6_RE = re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b')

_playwright = None
_browser = None

def start_playwright():
    global _playwright, _browser
    if not HAS_PLAYWRIGHT: return
    if _playwright is None: _playwright = sync_playwright().start()
    if _browser is None: _browser = _playwright.chromium.launch(headless=True, args=['--no-sandbox','--disable-dev-shm-usage'])

def stop_playwright():
    global _playwright, _browser
    try:
        if _browser: _browser.close(); _browser=None
        if _playwright: _playwright.stop(); _playwright=None
    except Exception: pass

@lru_cache(maxsize=256)
def fetch_ips_via_playwright_cached(domain):
    return fetch_ips_via_playwright(domain)

def fetch_ips_via_playwright(domain, timeout_s=10):
    results=[]
    seen=set()
    if not HAS_PLAYWRIGHT: return []
    page=None
    try:
        start_playwright()
        global _browser
        page=_browser.new_page()
        try: page.goto(f"https://www.nslookup.io/?q={domain}", wait_until='networkidle', timeout=timeout_s*1000)
        except PlaywrightTimeoutError:
            try: page.goto(f"https://www.nslookup.io/?q={domain}", timeout=timeout_s*1000); page.wait_for_timeout(800)
            except Exception: pass
        page.wait_for_timeout(800)
        try: body_text = page.evaluate("() => document.body.innerText")
        except Exception: body_text = page.content()
        for m in IPV4_RE.finditer(body_text):
            ip=m.group(0)
            if ip not in seen: seen.add(ip); results.append({'ip':ip,'type':'IPv4','source':'nslookup.io-playwright'})
        for m in IPV6_RE.finditer(body_text):
            ip6=m.group(0)
            if ip6 not in seen: seen.add(ip6); results.append({'ip':ip6,'type':'IPv6','source':'nslookup.io-playwright'})
    finally:
        try: 
            if page and not page.is_closed(): page.close()
        except Exception: pass
    return results

DOH_SERVERS=["https://cloudflare-dns.com/dns-query","https://dns.google/resolve"]

def resolve_domain_doh(name, timeout=3):
    results=[]
    seen=set()
    for server in DOH_SERVERS:
        for qtype in ("A","AAAA"):
            try:
                if "cloudflare" in server:
                    resp=requests.get(server, params={"name":name,"type":qtype}, headers={"Accept":"application/dns-json"}, timeout=timeout)
                    data=resp.json()
                    for ans in data.get("Answer", []):
                        ip=ans.get("data")
                        if ip and ip not in seen: seen.add(ip); results.append({'ip':ip,'type':'IPv4' if qtype=='A' else 'IPv6','source':f'doh:{server}:{qtype}'})
            except Exception: continue
    return results

def resolve_with_dnspython(name):
    results=[]
    seen=set()
    if not HAS_DNSPYTHON: return results
    public=["8.8.8.8","1.1.1.1","9.9.9.9"]
    import dns.resolver
    for server in public:
        try:
            resolver=dns.resolver.Resolver(configure=False)
            resolver.nameservers=[server]; resolver.lifetime=2
            for qtype in ("A","AAAA"):
                try:
                    ans=resolver.resolve(name,qtype)
                    for r in ans:
                        ip=r.to_text()
                        if ip not in seen: seen.add(ip); results.append({'ip':ip,'type':'IPv4' if qtype=='A' else 'IPv6','source':f'dns:{server}:{qtype}'})
                except Exception: pass
        except Exception: pass
    return results

def resolve_fallback_socket(name):
    results=[]
    seen=set()
    try:
        infos=socket.getaddrinfo(name,None)
        for info in infos:
            ip=info[4][0]
            if ip not in seen: seen.add(ip); results.append({'ip':ip,'type':'IPv4' if IPV4_RE.fullmatch(ip) else 'IPv6','source':'socket.getaddrinfo'})
    except Exception: pass
    return results

def get_ips_from_nslookupio_playwright_or_fallback(domain):
    try:
        if HAS_PLAYWRIGHT:
            ips=fetch_ips_via_playwright_cached(domain)
            if ips: return ips
    except Exception: pass
    doh=resolve_domain_doh(domain)
    if doh: return doh
    dnsr=resolve_with_dnspython(domain)
    if dnsr: return dnsr
    return resolve_fallback_socket(domain)

def geoip_info(ip):
    try:
        r=requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,org,lat,lon,query,timezone,reverse,mobile",timeout=6)
        data=r.json()
        if data.get('status')=='success':
            return {'country':data.get('country'),'region':data.get('regionName'),'city':data.get('city'),'isp':data.get('isp'),'org':data.get('org'),'lat':data.get('lat'),'lon':data.get('lon'),'timezone':data.get('timezone'),'hostname':data.get('reverse'),'mobile':data.get('mobile')}
    except Exception: pass
    return {}

def ping_ip(ip):
    try: r=ping(ip,count=1,timeout=2); return round(r.rtt_avg_ms,2)
    except Exception: return None

def hostname_of_ip(ip):
    try: return socket.gethostbyaddr(ip)[0]
    except Exception: return None

def enrich_ip_object(ipobj,do_geo=True):
    ipobj['ping']=ping_ip(ipobj['ip'])
    ipobj['hostname']=ipobj.get('hostname') or hostname_of_ip(ipobj['ip'])
    if do_geo: ipobj.update(geoip_info(ipobj['ip']))
    return ipobj

@app.route('/api/lookup',methods=['POST'])
def api_lookup():
    data=request.get_json() or {}
    domain=(data.get('domain') or '').strip()
    if not domain: return jsonify({'error':'Domaine manquant'}),400
    try: ip_objs=get_ips_from_nslookupio_playwright_or_fallback(domain)
    except Exception as e: return jsonify({'error':str(e)}),500
    enriched=[]
    with ThreadPoolExecutor(max_workers=min(12,max(1,len(ip_objs) or 1))) as ex:
        futures={ex.submit(enrich_ip_object,ipobj,True):ipobj for ipobj in ip_objs}
        for fut in as_completed(futures):
            try: enriched.append(fut.result())
            except Exception: enriched.append(futures[fut])
    return jsonify({'results':enriched})

@app.route('/')
def index():
    return render_template_string("""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Domain → IP Lookup</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<style>
body{font-family:sans-serif;background:#0f1115;color:#fff;margin:0;padding:0;}
.navbar{display:flex;justify-content:center;align-items:center;gap:20px;padding:14px;background:#0b0d10;box-shadow:0 2px 10px rgba(0,0,0,0.6);}
.brand{font-weight:800;font-size:18px;background:linear-gradient(90deg,#a855f7,#9333ea);-webkit-background-clip:text;color:transparent;}
.tab{padding:10px 16px;border-radius:10px;color:#cbd5e1;background:transparent;border:none;cursor:pointer;font-weight:700;transition:0.2s;}
.tab.active{background:linear-gradient(90deg,#a855f7,#9333ea);box-shadow:0 6px 18px rgba(168,85,247,0.18);color:#071021;}
.tab:hover{box-shadow:0 0 12px #a855f7;transform:scale(1.05);}
.container{padding:18px;display:flex;flex-direction:column;align-items:center;gap:18px;}
.panel{width:100%;max-width:1100px;}
.form{display:flex;gap:10px;align-items:center;justify-content:center;}
input{flex:1;padding:10px;border-radius:8px;border:none;background:#071021;color:#fff;font-size:16px;}
button.btn{padding:10px 16px;border:none;border-radius:8px;font-weight:700;color:#071021;background:linear-gradient(90deg,#a855f7,#9333ea);cursor:pointer;transition:all 0.2s;}
button.btn:hover{transform:scale(1.03);box-shadow:0 0 12px #a855f7;}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-top:16px;justify-items:center;}
.leftbox,.rightbox{background:#0f1724;padding:18px;border-radius:12px;min-height:220px;width:100%;}
.domain-display{font-size:20px;font-weight:800;background:linear-gradient(90deg,#a855f7,#9333ea);-webkit-background-clip:text;color:transparent;margin-bottom:8px;}
.meta{color:#9aa3b2;font-size:13px;margin-bottom:12px;text-align:center;}
.cards{display:flex;flex-direction:column;gap:12px;}
.card{background:#111827;padding:14px;border-radius:10px;transition:0.2s;cursor:pointer;}
.card:hover{transform:translateY(-4px);box-shadow:0 8px 20px rgba(168,85,247,0.12);}
.card-left{display:flex;align-items:center;font-weight:700;gap:8px;flex-wrap:wrap;}
.badge{padding:4px 8px;border-radius:10px;font-size:12px;font-weight:800;background:linear-gradient(90deg,#a855f7,#9333ea);color:#071021;}
.copy-btn{cursor:pointer;font-size:12px;color:#a855f7;}
.details{max-height:0;overflow:hidden;transition:max-height 0.28s ease;font-size:13px;margin-top:8px;color:#cbd5e1;line-height:1.4;}
.details.show{max-height:800px;}
.loader{border:4px solid #0b0b0b;border-top:4px solid #a855f7;border-radius:50%;width:24px;height:24px;animation:spin 1s linear infinite;margin-left:8px;}
@keyframes spin{to{transform:rotate(360deg)}}
#map{height:200px;width:100%;border-radius:10px;margin-top:6px;}
.faq-card{background:#071021;padding:14px;border-radius:10px;color:#cbd5e1;text-align:center;}
.small{font-size:13px;color:#9aa3b2;}
@media(max-width:900px){.grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="navbar">
  <div class="brand">Domain → IP Lookup</div>
  <button class="tab active" data-tab="search">Recherche</button>
  <button class="tab" data-tab="faq">FAQ</button>
</div>
<div class="container">
  <div class="panel" id="searchPanel">
    <div class="form">
      <input id="domain" placeholder="ex: example.com ou 8.8.8.8">
      <button id="go" class="btn">Chercher</button>
      <button id="refresh" class="btn">Rafraîchir</button>
      <button id="export" class="btn">Export CSV</button>
      <div id="loader" class="loader" style="display:none"></div>
    </div>
    <div class="grid">
      <div class="leftbox">
        <div class="domain-display" id="domainText">—</div>
        <div class="meta" id="metaText">Entrez un domaine et clique sur Chercher</div>
      </div>
      <div class="rightbox">
        <div id="cards" class="cards"><div class="small">Aucune recherche effectuée</div></div>
      </div>
    </div>
  </div>
  <div class="panel" id="faqPanel" style="display:none">
    <div class="faq-card">
      <h2>FAQ — Qu'est-ce qu'un domaine ?</h2>
      <p><strong>Domaine :</strong> un nom lisible qui correspond à une ou plusieurs ressources sur Internet (ex: <code>example.com</code>).</p>
      <p><strong>URL :</strong> l'adresse complète d'une ressource incluant protocole, domaine et chemin (ex: <code>https://example.com/page</code>).</p>
      <p class="small">Ne confondez pas : le domaine est la partie «nom», l'URL est l'adresse complète.</p>
    </div>
  </div>
</div>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script>
const tabs=document.querySelectorAll('.tab')
const panels={'search':document.getElementById('searchPanel'),'faq':document.getElementById('faqPanel')}
tabs.forEach(t=>t.addEventListener('click',()=>{tabs.forEach(x=>x.classList.remove('active')); t.classList.add('active'); Object.keys(panels).forEach(k=>panels[k].style.display='none'); panels[t.dataset.tab].style.display='block'}))

const go=document.getElementById('go')
const refresh=document.getElementById('refresh')
const exportBtn=document.getElementById('export')
const domainInput=document.getElementById('domain')
const domainText=document.getElementById('domainText')
const metaText=document.getElementById('metaText')
const cards=document.getElementById('cards')
const loader=document.getElementById('loader')
let resultsData=[]

function showLoader(show){loader.style.display=show?'inline-block':'none'}
function copyText(text){navigator.clipboard.writeText(text)}
function clearCards(){cards.innerHTML=''}
function renderResults(domain,results){
    domainText.textContent=domain
    metaText.textContent='Dernier check: '+new Date().toLocaleString()
    clearCards()
    resultsData=results||[]
    if(!resultsData.length){cards.innerHTML='<div class="small">Aucune IP trouvée</div>'; return}
    resultsData.forEach((r,idx)=>{
        const div=document.createElement('div'); div.className='card'
        div.innerHTML=`
        <div class="card-left">${r.ip} <span class="badge">${r.type||'-'}</span> <span class="copy-btn" onclick="copyText('${r.ip}')">Copier</span></div>
        <div class="details">
            Hostname: ${r.hostname||'-'}<br>
            Ville: ${r.city||'-'}<br>
            Région: ${r.region||'-'}<br>
            Pays: ${r.country||'-'}<br>
            ISP: ${r.isp||r.org||'-'}<br>
            Lat: ${r.lat||'-'}, Lon: ${r.lon||'-'}<br>
            Fuseau: ${r.timezone||'-'}<br>
            Mobile: ${r.mobile!==undefined?r.mobile:'-'}<br>
            Ping: ${r.ping!==null&&r.ping!==undefined?r.ping+' ms':'N/A'}
            <div id="map_${idx}"></div>
        </div>
        `
        const left=div.querySelector('.card-left')
        left.addEventListener('click',()=>{const det=div.querySelector('.details'); det.classList.toggle('show'); if(det.classList.contains('show')&&r.lat&&r.lon){const mapDiv=div.querySelector(`#map_${idx}`); if(mapDiv&&mapDiv.innerHTML.trim()===''){mapDiv.style.minHeight='200px'; const map=L.map(mapDiv).setView([r.lat,r.lon],5); L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png',{attribution:'&copy; OpenStreetMap contributors'}).addTo(map); L.marker([r.lat,r.lon]).addTo(map)}}})
        cards.appendChild(div)
    })
}

async function lookup(domain){
    showLoader(true)
    domainText.textContent='…'
    metaText.textContent='Recherche…'
    clearCards()
    try{
        const res=await fetch('/api/lookup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({domain})})
        const data=await res.json()
        showLoader(false)
        if(data.error){metaText.textContent='Erreur: '+data.error; cards.innerHTML='<div class="small">Impossible de récupérer</div>';return}
        renderResults(domain,data.results)
    }catch(e){showLoader(false); metaText.textContent='Erreur réseau'; cards.innerHTML='<div class="small">Impossible de contacter le serveur</div>'}
}

go.addEventListener('click',()=>{const d=domainInput.value.trim(); if(d)lookup(d)})
refresh.addEventListener('click',()=>{const d=domainInput.value.trim(); if(d)lookup(d)})
exportBtn.addEventListener('click',()=>{
    if(!resultsData.length){alert('Aucune donnée à exporter'); return}
    let csv='IP,Type,Hostname,City,Region,Country,ISP,Lat,Lon,Timezone,Mobile,Ping\\n'
    resultsData.forEach(r=>{csv+=`${r.ip},${r.type||''},${r.hostname||''},${r.city||''},${r.region||''},${r.country||''},${r.isp||r.org||''},${r.lat||''},${r.lon||''},${r.timezone||''},${r.mobile!==undefined?r.mobile:''},${r.ping!==null&&r.ping!==undefined?r.ping:''}\\n`})
    const blob=new Blob([csv],{type:'text/csv'})
    const url=URL.createObjectURL(blob)
    const a=document.createElement('a'); a.href=url; a.download='results.csv'; a.click(); URL.revokeObjectURL(url)
})
</script>
</body>
</html>""")

if __name__=="__main__":
    app.run(host='0.0.0.0',port=5000,debug=True)

