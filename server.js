const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const session = require("express-session");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const DB_PATH = path.join(__dirname, "data", "db.json");
const MEDIA_DIR = path.join(__dirname, "public", "media");
const SESSION_SECRET = process.env.SESSION_SECRET || "local-dev-only-secret";

app.set("trust proxy", 1);
app.use(express.json());
app.use(express.urlencoded({extended:true}));
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 1000*60*60*24*7
  }
}));
app.use(express.static(path.join(__dirname, "public")));

function readDB(){ return JSON.parse(fs.readFileSync(DB_PATH, "utf8")); }
function writeDB(db){ fs.writeFileSync(DB_PATH, JSON.stringify(db,null,2)); }
function creatorBySlug(db, slug){ return db.creators.find(c => c.slug === slug); }
function creatorById(db, id){ return db.creators.find(c => c.id === id); }
function currentUser(db, req){ return db.users.find(u => u.id === req.session.userId); }
function cleanName(s){ return String(s||"").replace(/[^\w .()\-]/g,"").slice(0,80) || "upload"; }
function slugify(s){ return String(s||"").toLowerCase().trim().replace(/[^a-z0-9]+/g,"-").replace(/^-|-$/g,"").slice(0,30); }
function publicCreator(c){
  return {
    id:c.id, slug:c.slug, displayName:c.displayName, currency:c.currency,
    messageTiers:c.messageTiers, sounds:c.sounds, memes:c.memes,
    platformFeePercent:c.platformFeePercent||10
  };
}
function requireAuth(req,res,next){
  if(!req.session.userId) return res.status(401).json({error:"Login required"});
  next();
}
function requireCreator(req,res,next){
  const db=readDB(); const u=currentUser(db,req);
  if(!u) return res.status(401).json({error:"Login required"});
  const c=creatorById(db,u.creatorId);
  if(!c) return res.status(403).json({error:"Creator account missing"});
  req.db=db; req.user=u; req.creator=c; next();
}

const storage = multer.diskStorage({
  destination: (_,__,cb)=>cb(null,MEDIA_DIR),
  filename: (_,file,cb)=>cb(null, Date.now()+"-"+cleanName(file.originalname))
});
const upload = multer({storage, limits:{fileSize:25*1024*1024}});

app.get("/", (req,res)=>res.sendFile(path.join(__dirname,"public","home.html")));
app.get("/creator/:slug", (req,res)=>{
  const db=readDB(); const c=creatorBySlug(db,req.params.slug);
  if(!c) return res.status(404).send("Creator not found");
  res.sendFile(path.join(__dirname,"public","viewer.html"));
});

app.post("/api/auth/signup", async (req,res)=>{
  const db=readDB();
  const email=String(req.body.email||"").trim().toLowerCase();
  const password=String(req.body.password||"");
  const displayName=String(req.body.displayName||"").trim().slice(0,50);
  let slug=slugify(req.body.slug||displayName);
  if(!email || password.length<6 || !displayName || !slug) return res.status(400).json({error:"Name, valid email, 6+ char password and username required"});
  if(db.users.some(u=>u.email===email)) return res.status(409).json({error:"Email already registered"});
  if(db.creators.some(c=>c.slug===slug)) return res.status(409).json({error:"Username already taken"});
  const uid=crypto.randomUUID(), cid=crypto.randomUUID();
  db.users.push({id:uid,email,passwordHash:await bcrypt.hash(password,10),creatorId:cid});
  db.creators.push({
    id:cid, ownerUserId:uid, slug, displayName, currency:"INR", platformFeePercent:10, paymentMode:"test",
    payout:{upiId:"",status:"not_configured"},
    messageTiers:[{max:50,price:20},{max:100,price:40},{max:150,price:70},{max:200,price:100}],
    sounds:[], memes:[], transactions:[]
  });
  writeDB(db);
  req.session.userId=uid;
  res.json({ok:true,slug});
});

app.post("/api/auth/login", async (req,res)=>{
  const db=readDB();
  const email=String(req.body.email||"").trim().toLowerCase();
  const u=db.users.find(x=>x.email===email);
  if(!u || !(await bcrypt.compare(String(req.body.password||""),u.passwordHash))) return res.status(401).json({error:"Invalid email or password"});
  req.session.userId=u.id;
  const c=creatorById(db,u.creatorId);
  res.json({ok:true,slug:c?.slug});
});
app.post("/api/auth/logout",(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get("/api/auth/me",(req,res)=>{
  const db=readDB(); const u=currentUser(db,req);
  if(!u) return res.status(401).json({error:"Not logged in"});
  const c=creatorById(db,u.creatorId);
  res.json({email:u.email, creator: c ? {slug:c.slug,displayName:c.displayName} : null});
});

app.get("/api/creator/:slug", (req,res)=>{
  const db=readDB(); const c=creatorBySlug(db,req.params.slug);
  if(!c) return res.status(404).json({error:"Creator not found"});
  res.json(publicCreator(c));
});

app.get("/api/dashboard", requireCreator, (req,res)=>{
  const c=req.creator, tx=c.transactions||[];
  const paid=tx.filter(x=>["paid","test"].includes(x.status));
  const gross=paid.reduce((a,b)=>a+Number(b.amount||0),0);
  const platformFee=paid.reduce((a,b)=>a+Number(b.platformFee||0),0);
  const creatorNet=paid.reduce((a,b)=>a+Number(b.creatorNet||0),0);
  res.json({...c, stats:{grossIncome:gross,platformFee,creatorNet,totalChats:tx.length,activeSounds:c.sounds.filter(x=>x.enabled).length}, transactions:tx.slice().reverse()});
});

app.post("/api/test-payment/:slug", (req,res)=>{
  const db=readDB(); const c=creatorBySlug(db,req.params.slug);
  if(!c) return res.status(404).json({error:"Creator not found"});
  const body=req.body||{};
  const gross=Math.max(0,Number(body.amount||0));
  const feePct=Number(c.platformFeePercent||10);
  const platformFee=Math.round(gross*feePct)/100;
  const creatorNet=Math.round((gross-platformFee)*100)/100;
  const safe={
    creatorSlug:c.slug,
    name:String(body.name||"Viewer").slice(0,30),
    message:String(body.message||"").slice(0,200),
    soundId:String(body.soundId||""),
    memeId:String(body.memeId||""),
    amount:gross, platformFee, creatorNet
  };
  const sound=c.sounds.find(x=>x.id===safe.soundId && x.enabled);
  const meme=c.memes.find(x=>x.id===safe.memeId && x.enabled);
  safe.soundFile=sound?.file||""; safe.memeFile=meme?.file||"";
  c.transactions=c.transactions||[];
  c.transactions.push({
    id:crypto.randomUUID(),viewer:safe.name,message:safe.message,amount:gross,
    platformFee,creatorNet,status:"test",createdAt:new Date().toISOString()
  });
  writeDB(db);
  io.to("creator:"+c.slug).emit("show-alert",safe);
  res.json({ok:true, breakdown:{gross,platformFee,creatorNet}});
});

app.post("/api/dashboard/payout", requireCreator, (req,res)=>{
  req.creator.payout={upiId:String(req.body.upiId||"").trim().slice(0,80),status:"saved-test"};
  writeDB(req.db); res.json({ok:true});
});

app.post("/api/dashboard/item/:type/:id", requireCreator, (req,res)=>{
  const c=req.creator;
  const list=req.params.type==="sound"?c.sounds:c.memes;
  const item=list.find(x=>x.id===req.params.id);
  if(!item) return res.status(404).json({error:"Item not found"});
  if(req.body.name!==undefined) item.name=String(req.body.name).slice(0,60);
  if(req.body.price!==undefined) item.price=Math.max(0,Number(req.body.price||0));
  if(req.body.enabled!==undefined) item.enabled=Boolean(req.body.enabled);
  writeDB(req.db); res.json({ok:true,item});
});

app.delete("/api/dashboard/item/:type/:id", requireCreator, (req,res)=>{
  const key=req.params.type==="sound"?"sounds":"memes";
  req.creator[key]=req.creator[key].filter(x=>x.id!==req.params.id);
  writeDB(req.db); res.json({ok:true});
});

app.post("/api/dashboard/upload/:type", requireCreator, upload.single("file"), (req,res)=>{
  if(!req.file) return res.status(400).json({error:"Missing file"});
  const isSound=req.params.type==="sound";
  const ext=path.extname(req.file.filename).toLowerCase();
  if(isSound && ![".mp3",".wav",".m4a"].includes(ext)) return res.status(400).json({error:"Use MP3/WAV/M4A"});
  if(!isSound && ![".mp4",".gif",".webm"].includes(ext)) return res.status(400).json({error:"Use MP4/GIF/WEBM"});
  const list=isSound?req.creator.sounds:req.creator.memes;
  list.push({
    id:(isSound?"s":"m")+Date.now(),
    name:String(req.body.name||path.parse(req.file.originalname).name).slice(0,60),
    file:"/media/"+req.file.filename,
    price:Math.max(0,Number(req.body.price||0)),
    enabled:true
  });
  writeDB(req.db); res.json({ok:true});
});

io.on("connection", socket=>socket.on("join-creator", slug=>socket.join("creator:"+String(slug||""))));

const PORT = process.env.PORT || 3000;
server.listen(PORT, "0.0.0.0", ()=>{
  console.log(`Stream Alert MVP V5 running on port ${PORT}`);
  console.log(`Home:      http://localhost:${PORT}/`);
  console.log(`Demo Login: ansh@example.com / ansh123`);
  console.log(`Viewer:    http://localhost:${PORT}/creator/ansh`);
  console.log(`Dashboard: http://localhost:${PORT}/dashboard.html`);
  console.log(`OBS:       http://localhost:${PORT}/overlay.html?creator=ansh`);
});
