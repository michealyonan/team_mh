// Multi-session WhatsApp pilot. App login is checked by the app server on every request.
const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const QRCode=require('qrcode');
const {default:makeWASocket,useMultiFileAuthState,DisconnectReason,fetchLatestBaileysVersion}=require('@whiskeysockets/baileys');
const PORT=Number(process.env.PORT||8787),ROOT=process.env.AUTH_DIR||'/data/auth';
const VERIFY='https://team-mh.michealuonanayad.workers.dev/api/auth/me';
const ORIGINS=new Set(['https://team-mh.michealuonanayad.workers.dev','https://michealyonan.github.io']);
const MAX=2,IDLE=10*60*1000,sessions=new Map(),pending=new Map();
// slot '1' keeps the original id so existing pairings survive; slots 2-3 get their own session dirs (Micheal 19189350)
function idFor(u,slot){return crypto.createHash('sha256').update(slot==='1'?('team-mh:'+u):('team-mh:'+u+':'+slot)).digest('hex')}
let versionPromise;
const logger={level:'silent',trace(){},debug(){},info(){},warn(){},error(){},fatal(){},child(){return this}};
function close(s){s.closed=true;for(const m of s.queue)s.receipts.set(m.id,{state:'failed',error:'session_closed'});s.queue=[];clearTimeout(s.retry);try{s.sock?.end(new Error('idle or manual disconnect'))}catch{}sessions.delete(s.id)}
function summary(s){return s?{state:s.state,phone:s.sock?.user?.id?.split(':')[0]?.split('@')[0]||'',pending:s.queue.length,sending:s.sending,error:s.error||'',qrAge:s.qrAt?Date.now()-s.qrAt:null}:{state:'offline',pending:0,sending:false}}
async function open(s){
 const {state,saveCreds}=await useMultiFileAuthState(path.join(ROOT,s.id));
 versionPromise ||= fetchLatestBaileysVersion().catch(()=>({version:undefined}));
 const {version}=await versionPromise;
 if(s.closed)return;
 const sock=makeWASocket({version,auth:state,printQRInTerminal:false,browser:['Team MH','Chrome','1.0'],logger});s.sock=sock;
 sock.ev.on('creds.update',saveCreds);
 sock.ev.on('connection.update',u=>{
  if(s.closed||s.sock!==sock)return;
  if(u.qr){s.qr=u.qr;s.qrAt=Date.now();s.state='qr'}
  if(u.connection==='open'){s.qr=null;s.state='connected';s.error='';console.log('session connected')}
  if(u.connection==='close'){
   const code=u.lastDisconnect?.error?.output?.statusCode||0;s.state='disconnected';s.qr=null;s.error='connection_'+code;console.log('session disconnected',code);
   if(code===DisconnectReason.loggedOut){s.closed=true;sessions.delete(s.id);fs.rmSync(path.join(ROOT,s.id),{recursive:true,force:true});return}
   if(++s.retries>4){close(s);return}
   s.retry=setTimeout(()=>open(s).catch(()=>{s.error='restart_failed';close(s)}),5000);
  }
 });
}
async function connect(id,owner,slot){
 if(sessions.has(id))return sessions.get(id);
 if(pending.has(id))return pending.get(id);
 if(sessions.size>=MAX)throw Object.assign(new Error('capacity_full'),{status:429});
 const s={id,owner,slot,state:'starting',qr:null,qrAt:0,retries:0,last:Date.now(),queue:[],sending:false,closed:false,receipts:new Map()};sessions.set(id,s);
 const p=open(s).then(()=>s).catch(e=>{close(s);throw e}).finally(()=>pending.delete(id));pending.set(id,p);return p;
}
async function pump(s){if(s.sending)return;s.sending=true;try{while(s.queue.length&&!s.closed){const m=s.queue.shift();if(s.state!=='connected'){s.receipts.set(m.id,{state:'failed',error:'not_connected'});continue}try{const wait=45000-(Date.now()-(s.lastSent||0));if(wait>0)await new Promise(r=>setTimeout(r,wait));if(s.closed||s.state!=='connected')throw Error('closed');await s.sock.sendMessage(m.to+'@s.whatsapp.net',{text:m.text});s.receipts.set(m.id,{state:'sent'});s.lastSent=Date.now();s.last=Date.now()}catch{ s.receipts.set(m.id,{state:'failed',error:'send_failed'})}if(s.queue.length)await new Promise(r=>setTimeout(r,45000));}}finally{s.sending=false}}
setInterval(()=>{for(const s of sessions.values())if(!s.sending&&Date.now()-s.last>IDLE)close(s)},60000).unref();
http.createServer(async(req,res)=>{
 const origin=req.headers.origin||'';
 const headers={'content-type':'application/json; charset=utf-8','cache-control':'no-store','vary':'Origin'};
 if(ORIGINS.has(origin)){headers['access-control-allow-origin']=origin;headers['access-control-allow-headers']='authorization,content-type';headers['access-control-allow-methods']='GET,POST,OPTIONS'}
 const send=(code,obj)=>{res.writeHead(code,headers);res.end(JSON.stringify(obj))};
 if(origin&&!ORIGINS.has(origin))return send(403,{error:'origin_forbidden'});
 if(req.method==='OPTIONS')return send(204,{});
 const url=new URL(req.url,'http://local');
 if(url.pathname==='/health')return send(200,{ok:true,mode:'per-user',limit:MAX,slots:true});
 if(!url.pathname.startsWith('/v1/'))return send(404,{error:'use_app_whatsapp_section'});
 const auth=req.headers.authorization||'';if(!/^Bearer [a-f0-9]{64}$/i.test(auth))return send(401,{error:'unauthorized'});
 try{
  const check=await fetch(VERIFY,{headers:{Authorization:auth},signal:AbortSignal.timeout(10000)});
  if(!check.ok)return send(check.status===401?401:503,{error:check.status===401?'login_required':'app_auth_unavailable'});
  const user=(await check.json()).profile;
  if(!user||!['admin','manager','sup'].includes(user.r))return send(403,{error:'forbidden'});
  let body={};if(req.method==='POST')body=await new Promise((resolve,reject)=>{let data='';req.on('data',c=>{data+=c;if(data.length>5000){reject(Object.assign(new Error('too_large'),{status:413}));req.destroy()}});req.on('end',()=>{try{resolve(JSON.parse(data||'{}'))}catch{reject(Object.assign(new Error('invalid_json'),{status:400}))}})});
  const slot=((req.method==='POST'?String(body.slot||''):(url.searchParams.get('slot')||''))||'1').trim();
  if(!/^[1-3]$/.test(slot))return send(400,{error:'invalid_slot'});
  const id=idFor(user.u,slot);
  let s=sessions.get(id);if(s)s.last=Date.now();
  if(url.pathname==='/v1/sessions'&&req.method==='GET')return send(200,{sessions:[...sessions.values()].filter(x=>x.owner===user.u).map(x=>({slot:x.slot,...summary(x)})),active:sessions.size,cap:MAX});
  if(url.pathname==='/v1/connect'&&req.method==='POST'){s=await connect(id,user.u,slot);return send(200,summary(s))}
  if(url.pathname==='/v1/status'&&req.method==='GET')return send(200,summary(s));
  if(url.pathname==='/v1/qr'&&req.method==='GET')return send(200,{...summary(s),qr:s?.qr?await QRCode.toDataURL(s.qr,{margin:2,width:330}):null});
  if(url.pathname==='/v1/disconnect'&&req.method==='POST'){if(s)close(s);return send(200,{ok:true})}
  if(url.pathname==='/v1/logout'&&req.method==='POST'){if(s){s.closed=true;try{await s.sock.logout()}catch{}close(s)}fs.rmSync(path.join(ROOT,id),{recursive:true,force:true});return send(200,{ok:true})}
  if(url.pathname==='/v1/send'&&req.method==='POST'){
   if(!s||s.state!=='connected')return send(409,{error:'not_connected'});
   const to=String(body.to||'').replace(/\D/g,''),text=String(body.text||'').trim(),key=String(body.id||'');
   if(!/^\d{10,15}$/.test(to)||!text||text.length>1000||!/^[-a-zA-Z0-9]{16,80}$/.test(key)||body.confirm!==true)return send(400,{error:'invalid_message_or_confirmation'});
   if(s.receipts.has(key))return send(200,{id:key,...s.receipts.get(key)});
   if(s.queue.length>=5)return send(429,{error:'queue_full'});
   if(s.receipts.size>100)s.receipts.delete(s.receipts.keys().next().value);
   s.receipts.set(key,{state:'queued'});s.queue.push({id:key,to,text});pump(s);return send(202,{id:key,state:'queued'});
  }
  if(url.pathname==='/v1/receipt'&&req.method==='GET')return send(200,s?.receipts.get(url.searchParams.get('id'))||{state:'unknown'});
  return send(404,{error:'not_found'});
 }catch(e){console.error('request failed',e.status||500);return send(e.status||503,{error:e.status?e.message:'service_unavailable'})}
}).listen(PORT,()=>console.log('per-user gateway listening',PORT));
