
require("dotenv").config();
const express=require("express"),path=require("path"),bcrypt=require("bcryptjs"),jwt=require("jsonwebtoken");
const {pool}=require("./local-db.js");
const app=express(),PORT=process.env.PORT||3000,JWT_SECRET=process.env.JWT_SECRET||"CHANGE_ME";
const fs=require("fs");
const smtpConfigDir=process.env.EMERGENCY_CONFIG_DIR||path.join(__dirname,"config");
const smtpConfigFile=path.join(smtpConfigDir,"smtp.json");
function loadSmtpConfig(){try{return JSON.parse(fs.readFileSync(smtpConfigFile,"utf8"))}catch(_e){return {host:"smtp.gmail.com",port:587,secure:false,user:"",pass:"",from:""}}}
function saveSmtpConfig(cfg){fs.mkdirSync(smtpConfigDir,{recursive:true});fs.writeFileSync(smtpConfigFile,JSON.stringify(cfg,null,2),"utf8");}
let smtpCfg=loadSmtpConfig();
function smtpTransport(){
  const nodemailer=require("nodemailer");
  if(!smtpCfg.user||!smtpCfg.pass) return null;
  return nodemailer.createTransport({host:smtpCfg.host||"smtp.gmail.com",port:Number(smtpCfg.port||587),secure:!!smtpCfg.secure,auth:{user:smtpCfg.user,pass:smtpCfg.pass},connectionTimeout:15000,greetingTimeout:15000,socketTimeout:20000});
}
app.use(express.json({limit:"12mb"}));

async function ensureV183Columns(){
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS phone text`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS email text`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS address text`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS postal_code text`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS city text`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS license_class text`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS entry_date date`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS active boolean NOT NULL DEFAULT true`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS assigned_vehicle_id uuid`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password boolean NOT NULL DEFAULT false`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at timestamptz DEFAULT now()`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS last_seen_at timestamptz`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS permissions jsonb NOT NULL DEFAULT '{}'::jsonb`);
}

async function ensureCompanySettings(){
  await q(`CREATE TABLE IF NOT EXISTS company_settings(
    id integer PRIMARY KEY DEFAULT 1,
    company_name text NOT NULL DEFAULT 'Emergency Delivery',
    legal_name text,
    address text,
    postal_code text,
    city text,
    country text DEFAULT 'Italien',
    vat_id text,
    tax_number text,
    phone text,
    email text,
    website text,
    iban text,
    bic text,
    bank_name text,
    footer_note text,
    updated_at timestamptz DEFAULT now(),
    CONSTRAINT company_settings_singleton CHECK(id=1)
  )`);
  await q(`INSERT INTO company_settings(id,company_name,country) VALUES(1,'Emergency Delivery','Italien') ON CONFLICT (id) DO NOTHING`);
}
app.use(express.static(path.join(__dirname,"public")));
const q=(s,p=[])=>pool.query(s,p).then(r=>r.rows);
ensureV183Columns().catch(err=>console.error('V183 schema init failed:',err));
ensureCompanySettings().catch(err=>console.error('Company settings init failed:',err));
async function auth(req,res,next){try{const t=(req.headers.authorization||"").replace("Bearer ","");const token=jwt.verify(t,JWT_SECRET);const u=(await q("select id,username,name,role,permissions,active from users where id=$1",[token.id]))[0];if(!u||u.active===false)return res.status(401).json({error:"Benutzer ist deaktiviert"});req.user={...token,username:u.username,permissions:u.permissions||{}};const hit=PERM_PATHS.find(([re])=>re.test(req.path));if(hit&&!hasPermission(req.user,hit[1]))return res.status(403).json({error:"Berechtigung fehlt: "+hit[1]});next()}catch(e){res.status(401).json({error:"Login required"})}}
const ROLE_DEFAULTS={Admin:{},Dispatcher:{auftrag_plus:true,customers:true,vehicles:true,calendar:true,documents:true,order360:true,operations:true,notifications:true},Driver:{auftrag_plus:false,customers:false,vehicles:false,calendar:false,documents:true,order360:false,operations:false,notifications:true,driver:true},Accounting:{auftrag_plus:false,customers:true,vehicles:false,calendar:true,documents:true,invoices:true,finance:true,order360:true,operations:false,notifications:true}};
const PERM_PATHS=[
  [/^\/api\/(trips|routes|planning|pricing|recurring-orders)/,'auftrag_plus'],[/^\/api\/customers/,'customers'],[/^\/api\/vehicles/,'vehicles'],[/^\/api\/calendar/,'calendar'],[/^\/api\/(documents|ddt)/,'documents'],[/^\/api\/invoices/,'invoices'],[/^\/api\/(finance|receivables|dunning)/,'finance'],[/^\/api\/(order-360|orders)/,'order360'],[/^\/api\/(operations|control-center)/,'operations'],[/^\/api\/notifications/,'notifications'],[/^\/api\/employees/,'users_manage'],[/^\/api\/company-settings/,'company'],[/^\/api\/driver/,'driver'],[/^\/api\/fleet/,'vehicles']
];
function hasPermission(user,key){if(user.role==='Admin')return true;const custom=user.permissions||{};if(Object.prototype.hasOwnProperty.call(custom,key))return !!custom[key];return !!((ROLE_DEFAULTS[user.role]||{})[key]);}
const roles=(...rs)=>(req,res,next)=>{if(!rs.includes(req.user.role))return res.status(403).json({error:"Not permitted"});const hit=PERM_PATHS.find(([re])=>re.test(req.path));if(hit&&!hasPermission(req.user,hit[1]))return res.status(403).json({error:"Berechtigung fehlt: "+hit[1]});next()};
async function audit(req,action,details){await q("INSERT INTO audit_log(user_id,user_name,role,action,details) VALUES($1,$2,$3,$4,$5)",[req.user.id,req.user.name,req.user.role,action,String(details)])}

// V176 Mitarbeiterakte
app.get("/api/employees", auth, roles("Admin","Dispatcher","Accounting","Driver"), async (req,res)=>{
  try{res.json(await q(`SELECT u.id,u.username,u.name,u.role,u.phone,u.email,u.address,u.postal_code,u.city,u.license_class,u.entry_date,u.active,u.assigned_vehicle_id,u.permissions,v.name AS vehicle_name,v.plate AS vehicle_plate FROM users u LEFT JOIN vehicles v ON v.id=u.assigned_vehicle_id ORDER BY u.name ASC`))}
  catch(e){res.status(500).json({error:e.message})}
});
app.get("/api/employee-vehicles", auth, roles("Admin","Dispatcher","Accounting","Driver"), async (req,res)=>{
  try{res.json(await q("SELECT id,name,plate FROM vehicles WHERE active=true ORDER BY name"))}catch(e){res.status(500).json({error:e.message})}
});
app.post("/api/employees", auth, roles("Admin"), async (req,res)=>{
  try{
    const {username,name,role,password,phone,email,address,postal_code,city,license_class,entry_date,active,assigned_vehicle_id,permissions}=req.body||{};
    if(!username||!name||!role||!password)return res.status(400).json({error:"Benutzername, Name, Rolle und Passwort sind erforderlich"});
    if(!["Admin","Dispatcher","Driver","Accounting"].includes(role))return res.status(400).json({error:"Ungültige Rolle"});
    const hash=await bcrypt.hash(password,12);
    const r=await q(`INSERT INTO users(username,name,role,password_hash,phone,email,address,postal_code,city,license_class,entry_date,active,assigned_vehicle_id,permissions) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING id,username,name,role,phone,email,address,postal_code,city,license_class,entry_date,active,assigned_vehicle_id,permissions`,
      [username.trim(),name.trim(),role,hash,phone||null,email||null,address||null,postal_code||null,city||null,license_class||null,entry_date||null,active!==false,assigned_vehicle_id||null,permissions&&typeof permissions==="object"?permissions:{}]);
    await audit(req,"EMPLOYEE_CREATED",`${name} (${role})`);res.status(201).json(r[0]);
  }catch(e){if(e.code==="23505")return res.status(409).json({error:"Benutzername bereits vorhanden"});res.status(500).json({error:e.message})}
});
app.patch("/api/employees/:id", auth, roles("Admin"), async (req,res)=>{
  try{
    const {name,role,password,phone,email,address,postal_code,city,license_class,entry_date,active,assigned_vehicle_id,permissions}=req.body||{};
    if(!name||!role)return res.status(400).json({error:"Name und Rolle sind erforderlich"});
    if(!["Admin","Dispatcher","Driver","Accounting"].includes(role))return res.status(400).json({error:"Ungültige Rolle"});
    let r;
    const vals=[name.trim(),role,phone||null,email||null,address||null,postal_code||null,city||null,license_class||null,entry_date||null,active!==false,assigned_vehicle_id||null,req.params.id];
    if(password){
      const hash=await bcrypt.hash(password,12);
      r=await q(`UPDATE users SET name=$1,role=$2,phone=$3,email=$4,address=$5,postal_code=$6,city=$7,license_class=$8,entry_date=$9,active=$10,assigned_vehicle_id=$11,permissions=$12,password_hash=$13 WHERE id=$14 RETURNING id,username,name,role,phone,email,address,postal_code,city,license_class,entry_date,active,assigned_vehicle_id,permissions`,
        [name.trim(),role,phone||null,email||null,address||null,postal_code||null,city||null,license_class||null,entry_date||null,active!==false,assigned_vehicle_id||null,permissions&&typeof permissions==="object"?permissions:{},hash,req.params.id]);
    }else r=await q(`UPDATE users SET name=$1,role=$2,phone=$3,email=$4,address=$5,postal_code=$6,city=$7,license_class=$8,entry_date=$9,active=$10,assigned_vehicle_id=$11,permissions=$12 WHERE id=$13 RETURNING id,username,name,role,phone,email,address,postal_code,city,license_class,entry_date,active,assigned_vehicle_id,permissions`,[name.trim(),role,phone||null,email||null,address||null,postal_code||null,city||null,license_class||null,entry_date||null,active!==false,assigned_vehicle_id||null,permissions&&typeof permissions==="object"?permissions:{},req.params.id]);
    if(!r.length)return res.status(404).json({error:"Mitarbeiter nicht gefunden"});
    await audit(req,"EMPLOYEE_UPDATED",`${r[0].name} (${r[0].role})`);res.json(r[0]);
  }catch(e){res.status(500).json({error:e.message})}
});
app.delete("/api/employees/:id", auth, roles("Admin"), async (req,res)=>{
  try{if(req.params.id===req.user.id)return res.status(400).json({error:"Der eigene Benutzer kann nicht gelöscht werden"});
    const r=await q("DELETE FROM users WHERE id=$1 RETURNING id,name,role",[req.params.id]);if(!r.length)return res.status(404).json({error:"Mitarbeiter nicht gefunden"});
    await audit(req,"EMPLOYEE_DELETED",`${r[0].name} (${r[0].role})`);res.json({ok:true})
  }catch(e){res.status(500).json({error:e.message})}
});
function maps(origin,dest,stops=[]){return "https://www.google.com/maps/dir/?api=1&origin="+encodeURIComponent(origin)+"&destination="+encodeURIComponent(dest)+(stops.length?"&waypoints="+encodeURIComponent(stops.join("|")):"")}

app.get("/api/health",async(req,res)=>{try{await q("select 1");res.json({ok:true})}catch(e){res.status(503).json({ok:false})}});
app.post("/api/login",async(req,res)=>{const u=(await q("select id,username,name,role,password_hash,must_change_password,active from users where username=$1",[String(req.body.username||"").trim()]))[0];if(!u||u.active===false||!(await bcrypt.compare(String(req.body.password||""),u.password_hash)))return res.status(401).json({error:"Benutzername oder Passwort ist falsch"});await q("update users set last_seen_at=now() where id=$1",[u.id]);res.json({token:jwt.sign({id:u.id,name:u.name,role:u.role},JWT_SECRET,{expiresIn:"12h"}),user:{id:u.id,username:u.username,name:u.name,role:u.role,must_change_password:!!u.must_change_password}})});
app.get("/api/me",auth,async(req,res)=>{
  try{const u=(await q("select id,username,name,role,email,phone,must_change_password,permissions from users where id=$1",[req.user.id]))[0];if(!u)return res.status(404).json({error:"Benutzer nicht gefunden"});res.json(u)}catch(e){res.status(500).json({error:e.message})}
});
app.patch("/api/me",auth,async(req,res)=>{
  try{const name=String(req.body.name||"").trim(),email=String(req.body.email||"").trim()||null,phone=String(req.body.phone||"").trim()||null;if(!name)return res.status(400).json({error:"Name ist erforderlich"});const r=await q("update users set name=$1,email=$2,phone=$3 where id=$4 returning id,username,name,role,email,phone,must_change_password",[name,email,phone,req.user.id]);if(!r[0])return res.status(404).json({error:"Benutzer nicht gefunden"});await audit(req,"PROFILE_UPDATED",r[0].username);res.json(r[0])}catch(e){res.status(500).json({error:e.message})}
});
app.post("/api/me/password",auth,async(req,res)=>{
  try{const current=String(req.body.currentPassword||""),next=String(req.body.newPassword||"");if(next.length<8)return res.status(400).json({error:"Das neue Passwort muss mindestens 8 Zeichen haben"});const u=(await q("select username,password_hash from users where id=$1",[req.user.id]))[0];if(!u||!(await bcrypt.compare(current,u.password_hash)))return res.status(400).json({error:"Aktuelles Passwort ist falsch"});if(current===next)return res.status(400).json({error:"Das neue Passwort muss sich vom alten unterscheiden"});const hash=await bcrypt.hash(next,12);await q("update users set password_hash=$2,must_change_password=false where id=$1",[req.user.id,hash]);await audit(req,"SELF_PASSWORD_CHANGED",u.username);res.json({ok:true})}catch(e){res.status(500).json({error:e.message})}
});

app.get("/api/state",auth,async(req,res)=>{await ensureCompanySettings();const [users,customers,trips,vehicles,invoices,stops,gps,company]=await Promise.all([
q("select id,name,role from users order by name"),q("select * from customers order by company"),q("select * from trips order by created_at desc"),q("select * from vehicles order by name"),
q("select * from invoices order by issue_date desc"),q("select * from trip_stops order by trip_id,stop_order"),Promise.resolve([]),q("select * from company_settings where id=1")]);
res.json({user:req.user,users,customers,trips,vehicles,invoices,stops,gps,company:company[0]||{}})});

app.get("/api/company-settings",auth,async(req,res)=>{
  try{await ensureCompanySettings();const r=await q("select * from company_settings where id=1");res.json(r[0]||{});}catch(e){res.status(500).json({error:e.message})}
});
app.patch("/api/company-settings",auth,roles("Admin"),async(req,res)=>{
  try{
    const b=req.body||{};
    const companyName=String(b.company_name||"").trim();
    if(!companyName)return res.status(400).json({error:"Firmenname ist erforderlich"});
    const fields={company_name:companyName,legal_name:String(b.legal_name||"").trim()||null,address:String(b.address||"").trim()||null,postal_code:String(b.postal_code||"").trim()||null,city:String(b.city||"").trim()||null,country:String(b.country||"").trim()||null,vat_id:String(b.vat_id||"").trim()||null,tax_number:String(b.tax_number||"").trim()||null,phone:String(b.phone||"").trim()||null,email:String(b.email||"").trim()||null,website:String(b.website||"").trim()||null,iban:String(b.iban||"").trim()||null,bic:String(b.bic||"").trim()||null,bank_name:String(b.bank_name||"").trim()||null,footer_note:String(b.footer_note||"").trim()||null};
    const r=await q(`update company_settings set company_name=$1,legal_name=$2,address=$3,postal_code=$4,city=$5,country=$6,vat_id=$7,tax_number=$8,phone=$9,email=$10,website=$11,iban=$12,bic=$13,bank_name=$14,footer_note=$15,updated_at=now() where id=1 returning *`,Object.values(fields));
    await audit(req,"COMPANY_SETTINGS_UPDATED",fields.company_name);res.json(r[0]);
  }catch(e){res.status(500).json({error:e.message})}
});

app.post("/api/customers",auth,roles("Admin","Dispatcher"),async(req,res)=>{const r=await q("insert into customers(company,vat_id,address,city,email,phone) values($1,$2,$3,$4,$5,$6) returning *",[req.body.company,req.body.vatId,req.body.address,req.body.city,req.body.email,req.body.phone]);await audit(req,"CUSTOMER_CREATED",r[0].company);res.json(r[0])});
app.post("/api/trips",auth,roles("Admin","Dispatcher"),async(req,res)=>{const w=+req.body.weightKg||0;if(w>1000)return res.status(400).json({error:"Maximum 1,000 KG"});const n=await q("select 'TRIP-'||extract(year from current_date)::int||'-'||lpad((coalesce(max(cast(split_part(trip_number,'-',3) as int)),0)+1)::text,4,'0') n from trips");const r=await q("insert into trips(trip_number,customer_id,weight_kg,pieces,status,driver_id,vehicle_id,route,notes,price_net) values($1,$2,$3,$4,'Planned',$5,$6,$7,$8,$9) returning *",[n[0].n,req.body.customerId,w,+req.body.pieces||1,req.body.driverId||null,req.body.vehicleId||null,req.body.route||"",req.body.notes||"",+req.body.priceNet||0]);await audit(req,"TRIP_CREATED",r[0].trip_number);res.json(r[0])});
app.post("/api/trips/:id/stops",auth,roles("Admin","Dispatcher"),async(req,res)=>{const c=await q("select coalesce(max(stop_order),0)+1 n from trip_stops where trip_id=$1",[req.params.id]);const r=await q("insert into trip_stops(trip_id,stop_order,address,customer_name,planned_time) values($1,$2,$3,$4,$5) returning *",[req.params.id,c[0].n,req.body.address,req.body.customerName,req.body.plannedTime||null]);res.json(r[0])});
app.post("/api/routes/optimize",auth,roles("Admin","Dispatcher"),async(req,res)=>{const ids=req.body.tripIds||[];if(!ids.length)return res.status(400).json({error:"No trips"});const ts=await q("select t.*,c.address,c.city,c.company from trips t left join customers c on c.id=t.customer_id where t.id=any($1::uuid[])",[ids]);const order=ts.sort((a,b)=>String(a.city||"").localeCompare(String(b.city||"")));const origin=req.body.origin||"Milano";const destination=req.body.destination||origin;const url=maps(origin,destination,order.map(x=>x.address||x.city).filter(Boolean));await audit(req,"ROUTE_OPTIMIZED",order.map(x=>x.trip_number).join(","));res.json({ordered:order.map((x,i)=>({position:i+1,id:x.id,tripNumber:x.trip_number,customer:x.company,address:x.address,city:x.city})),mapsUrl:url})});
app.patch("/api/trips/:id",auth,async(req,res)=>{const t=(await q("select * from trips where id=$1",[req.params.id]))[0];if(!t)return res.status(404).json({error:"Not found"});if(req.user.role==="Driver"&&t.driver_id!==req.user.id)return res.status(403).json({error:"Not your trip"});const allowed=["status","driver_id","vehicle_id","route","notes","current_lat","current_lng","signature_data","signature_at","delivery_photo","weight_kg","pieces","price_net"];const a=Object.keys(req.body).filter(k=>allowed.includes(k));if(!a.length)return res.json(t);const vals=a.map(k=>req.body[k]);const set=a.map((k,i)=>`${k}=$${i+1}`).join(",");const r=await q(`update trips set ${set},updated_at=now() where id=$${a.length+1} returning *`,[...vals,req.params.id]);await audit(req,"TRIP_UPDATED",r[0].trip_number);if(req.body.status==="Delivered"&&Number(r[0].price_net)>0){try{await createInvoice38(req,r[0].id)}catch(e){await autoInvoice(req,r[0]);}}res.json(r[0])});
async function autoInvoice(req,t){const exists=(await q("select id from invoices where trip_id=$1",[t.id]))[0];if(exists)return;const n=await q("select 'INV-'||extract(year from current_date)::int||'-'||lpad((coalesce(max(cast(split_part(invoice_number,'-',3) as int)),0)+1)::text,4,'0') n from invoices");const net=+t.price_net,vat=+(net*.22).toFixed(2);await q("insert into invoices(invoice_number,customer_id,trip_id,net,vat_rate,vat,gross,status,description) values($1,$2,$3,$4,22,$5,$6,'Open',$7)",[n[0].n,t.customer_id, t.id,net,vat,net+vat,"Automatiche Rechnung für "+t.trip_number]);await audit(req,"AUTO_INVOICE_CREATED",t.trip_number)}
app.post("/api/gps",auth,roles("Driver"),async(req,res)=>{const t=(await q("select id from trips where id=$1 and driver_id=$2",[req.body.tripId,req.user.id]))[0];if(!t)return res.status(404).json({error:"Trip not found"});const r=await q("insert into gps_points(trip_id,driver_id,lat,lng,accuracy) values($1,$2,$3,$4,$5) returning *",[t.id,req.user.id,req.body.lat,req.body.lng,req.body.accuracy||null]);await q("update trips set current_lat=$1,current_lng=$2,updated_at=now() where id=$3",[req.body.lat,req.body.lng,t.id]);res.json(r[0])});
app.post("/api/documents/ddt-manual",auth,roles("Admin","Dispatcher","Accounting"),async(req,res)=>{
  await q(`CREATE TABLE IF NOT EXISTS delivery_documents(
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(), trip_id uuid UNIQUE REFERENCES trips(id) ON DELETE CASCADE,
    document_number text UNIQUE NOT NULL, issued_at timestamptz DEFAULT now(), status text DEFAULT 'Open', proof_complete boolean DEFAULT false
  )`);

  try{
    const b=req.body||{};
    if(!b.customerId||!b.address)return res.status(400).json({error:"Kunde und Lieferadresse sind erforderlich"});
    const weight=Math.max(0,Number(b.weightKg)||0);
    if(weight>1000)return res.status(400).json({error:"Maximal 1.000 KG"});
    const n=await q("select 'TRIP-'||extract(year from current_date)::int||'-'||lpad((coalesce(max(cast(split_part(trip_number,'-',3) as int)),0)+1)::text,4,'0') n from trips");
    const route=[b.pickupAddress,b.address].filter(Boolean).join(" → ");
    const t=(await q(`insert into trips(trip_number,customer_id,weight_kg,pieces,status,driver_id,vehicle_id,route,notes,price_net)
      values($1,$2,$3,$4,'Planned',$5,$6,$7,$8,0) returning *`,
      [n[0].n,b.customerId,weight,Math.max(1,Number(b.pieces)||1),b.driverId||null,b.vehicleId||null,route,b.notes||null]))[0];
    await q(`insert into trip_stops(trip_id,stop_order,address,customer_name,planned_time)
      values($1,1,$2,$3,$4)`,[t.id,b.address,b.customerName||null,b.plannedTime||null]);
    const dn=await q(`select 'DDT-'||extract(year from current_date)::int||'-'||lpad(
      (coalesce(max(cast(split_part(document_number,'-',3) as int)),0)+1)::text,4,'0') n from delivery_documents`);
    const d=(await q(`insert into delivery_documents(trip_id,document_number,status,proof_complete)
      values($1,$2,'Open',false) returning *`,[t.id,dn[0].n]))[0];
    await audit(req,"MANUAL_DDT_CREATED",d.document_number);
    res.json({trip:t,ddt:d});
  }catch(e){res.status(400).json({error:e.message})}
});
app.post("/api/invoices",auth,roles("Admin","Accounting"),async(req,res)=>{
  try{
    const net=+req.body.net||0, rate=+req.body.vatRate||22;
    if(!req.body.customerId)return res.status(400).json({error:"Kunde ist erforderlich"});
    if(net<0)return res.status(400).json({error:"Netto darf nicht negativ sein"});
    const vat=+(net*rate/100).toFixed(2);
    const n=await q("select 'INV-'||extract(year from current_date)::int||'-'||lpad((coalesce(max(cast(split_part(invoice_number,'-',3) as int)),0)+1)::text,4,'0') n from invoices");
    const r=await q("insert into invoices(invoice_number,customer_id,trip_id,net,vat_rate,vat,gross,due_date,status,description) values($1,$2,$3,$4,$5,$6,$7,$8,'Open',$9) returning *",
      [n[0].n,req.body.customerId,req.body.tripId||null,net,rate,vat,net+vat,req.body.dueDate||null,req.body.description||"Trasportdienstleistung"]);
    await audit(req,"MANUAL_INVOICE_CREATED",r[0].invoice_number);
    res.json(r[0]);
  }catch(e){res.status(400).json({error:e.message})}
});
app.patch("/api/invoices/:id",auth,roles("Admin","Accounting"),async(req,res)=>{
  try{
    const old=(await q("select * from invoices where id=$1",[req.params.id]))[0];
    if(!old)return res.status(404).json({error:"Rechnung nicht gefunden"});
    const b=req.body||{};
    const customerId=b.customerId||old.customer_id;
    const net=b.net===undefined?Number(old.net):Number(b.net);
    const rate=b.vatRate===undefined?Number(old.vat_rate):Number(b.vatRate);
    if(net<0)return res.status(400).json({error:"Netto darf nicht negativ sein"});
    if(rate<0)return res.status(400).json({error:"USt.-Satz darf nicht negativ sein"});
    if(customerId && !(await q("select 1 from customers where id=$1",[customerId]))[0])return res.status(400).json({error:"Kunde nicht gefunden"});
    const vat=+(net*rate/100).toFixed(2), gross=+(net+vat).toFixed(2);
    const status=b.status||old.status;
    const r=await q(`update invoices set customer_id=$1,trip_id=$2,net=$3,vat_rate=$4,vat=$5,gross=$6,due_date=$7,status=$8,description=$9,paid_at=case when $8='Paid' then coalesce(paid_at,now()) else null end where id=$10 returning *`,
      [customerId,b.tripId===undefined?old.trip_id:(b.tripId||null),net,rate,vat,gross,b.dueDate===undefined?old.due_date:(b.dueDate||null),status,b.description===undefined?old.description:(b.description||null),req.params.id]);
    await audit(req,"INVOICE_UPDATED",r[0].invoice_number);
    res.json(r[0]);
  }catch(e){res.status(400).json({error:e.message})}
});
app.patch("/api/documents/ddt/:id",auth,roles("Admin","Dispatcher","Accounting"),async(req,res)=>{
  try{
    const d=(await q("select * from delivery_documents where id=$1",[req.params.id]))[0];
    if(!d)return res.status(404).json({error:"Lieferschein nicht gefunden"});
    const t=(await q("select * from trips where id=$1",[d.trip_id]))[0];
    if(!t)return res.status(404).json({error:"Zugehöriger Auftrag nicht gefunden"});
    const b=req.body||{};
    const customerId=b.customerId||t.customer_id;
    if(customerId && !(await q("select 1 from customers where id=$1",[customerId]))[0])return res.status(400).json({error:"Kunde nicht gefunden"});
    const weight=b.weightKg===undefined?Number(t.weight_kg):Number(b.weightKg);
    const pieces=b.pieces===undefined?Number(t.pieces||1):Number(b.pieces);
    if(weight<0||weight>1000)return res.status(400).json({error:"Gewicht muss zwischen 0 und 1.000 KG liegen"});
    if(pieces<1)return res.status(400).json({error:"Stückzahl muss mindestens 1 sein"});
    const address=(b.address||"").trim();
    const pickup=(b.pickupAddress||"").trim();
    const route=[pickup,address].filter(Boolean).join(" → ");
    const tr=(await q(`update trips set customer_id=$1,weight_kg=$2,pieces=$3,driver_id=$4,vehicle_id=$5,route=$6,notes=$7,updated_at=now() where id=$8 returning *`,
      [customerId,weight,pieces,b.driverId||null,b.vehicleId||null,route,b.notes||null,t.id]))[0];
    const stop=(await q("select * from trip_stops where trip_id=$1 order by stop_order limit 1",[t.id]))[0];
    if(stop){
      await q(`update trip_stops set address=$1,customer_name=$2,planned_time=$3 where id=$4`,[address,b.customerName||null,b.plannedTime||null,stop.id]);
    }else if(address){
      await q(`insert into trip_stops(trip_id,stop_order,address,customer_name,planned_time) values($1,1,$2,$3,$4)`,[t.id,address,b.customerName||null,b.plannedTime||null]);
    }
    const status=b.status||d.status;
    const updated=(await q("update delivery_documents set status=$1 where id=$2 returning *",[status,req.params.id]))[0];
    await audit(req,"DDT_UPDATED",updated.document_number);
    res.json({ddt:updated,trip:tr});
  }catch(e){res.status(400).json({error:e.message})}
});

app.get("/api/audit",auth,roles("Admin","Accounting"),async(req,res)=>res.json(await q("select * from audit_log order by created_at desc limit 500")));
app.get("/api/documents/invoice/:id",auth,async(req,res)=>{const i=(await q("select i.*,c.company,c.vat_id,c.address,c.city from invoices i join customers c on c.id=i.customer_id where i.id=$1",[req.params.id]))[0];if(!i)return res.status(404).send("Not found");res.type("html").send(doc("Fattura "+i.invoice_number,`<div class="top"><div><b>Emergency Delivery</b><p>Trasporti urgenti · Italia</p></div><div class="right">FATTURA<h1>${i.invoice_number}</h1>${i.issue_date.toISOString().slice(0,10)}</div></div><div class="grid"><div class="card"><small>CLIENTE</small><b>${i.company}</b><br>${i.address||""}<br>${i.city||""}<br>${i.vat_id||""}</div><div class="card"><small>PAGAMENTO</small>Scadenza: ${i.due_date?i.due_date.toISOString().slice(0,10):"—"}<br>Stato: ${i.status}</div></div><table><tr><th>Descrizione</th><th>Netto</th></tr><tr><td>${i.description||"Trasporto urgente"}</td><td>€ ${Number(i.net).toFixed(2)}</td></tr></table><p style="text-align:right">Imponibile € ${Number(i.net).toFixed(2)}<br>IVA ${i.vat_rate}% € ${Number(i.vat).toFixed(2)}<br><b style="font-size:20px">Totale € ${Number(i.gross).toFixed(2)}</b></p>`))});
app.get("/api/documents/delivery-note/:id",auth,async(req,res)=>{const t=(await q("select t.*,c.company,c.address,c.city from trips t join customers c on c.id=t.customer_id where t.id=$1",[req.params.id]))[0];if(!t)return res.status(404).send("Not found");const st=await q("select * from trip_stops where trip_id=$1 order by stop_order",[t.id]);res.type("html").send(doc("DDT "+t.trip_number,`<div class="top"><div><b>Emergency Delivery</b><p>Documento di consegna</p></div><div class="right">DDT<h1>${t.trip_number}</h1></div></div><div class="grid"><div class="card"><small>DESTINATARIO</small><b>${t.company}</b><br>${t.address||""}<br>${t.city||""}</div><div class="card"><small>FAHRZEUG / FAHRER</small>${t.vehicle_id||"—"} / ${t.driver_id||"—"}<br>${t.weight_kg} KG · ${t.pieces} pezzi</div></div><table><tr><th>Stop</th><th>Kunde</th><th>Adresse</th></tr>${st.map(s=>`<tr><td>${s.stop_order}</td><td>${s.customer_name||""}</td><td>${s.address}</td></tr>`).join("")}</table><div class="sign"><div>Firma mittente</div><div>Firma destinatario</div></div>`))});
function doc(title,b){return `<!doctype html><html><head><meta charset="utf-8"><title>${title}</title><style>@page{size:A4;margin:14mm}body{font-family:Arial;color:#172033}.sheet{max-width:800px;margin:auto;padding:20px}.top{display:flex;justify-content:space-between;border-bottom:3px solid #172033;padding-bottom:16px}.top b{font-size:28px}.right{text-align:right}.grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin:22px 0}.card{border:1px solid #ddd;border-radius:8px;padding:14px;margin:12px 0}small{display:block;color:#667085;margin-bottom:6px}table{width:100%;border-collapse:collapse;margin:18px 0}th,td{padding:9px;border-bottom:1px solid #ddd;text-align:left}.sign{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-top:50px}.sign div{height:80px;border:1px solid #ddd;padding:10px}@media print{.actions{display:none}}</style></head><body><div class="actions" style="text-align:center"><button onclick="print()">Stampa / Salva come PDF</button></div><main class="sheet">${b}</main></body></html>`}

app.get("/api/trips/:id/stops",auth,async(req,res)=>{
  try{
    const t=(await q("select id,driver_id from trips where id=$1",[req.params.id]))[0];
    if(!t)return res.status(404).json({error:"Tour nicht gefunden"});
    if(req.user.role==="Driver"&&t.driver_id!==req.user.id)return res.status(403).json({error:"Not permitted"});
    res.json(await q("select * from trip_stops where trip_id=$1 order by stop_order",[req.params.id]));
  }catch(e){res.status(500).json({error:e.message})}
});

app.patch("/api/stops/:id",auth,async(req,res)=>{
  const r=await q("UPDATE trip_stops SET status=COALESCE($1,status), arrived_at=CASE WHEN $1='Arrived' THEN NOW() ELSE arrived_at END, delivered_at=CASE WHEN $1='Delivered' THEN NOW() ELSE delivered_at END, notes=COALESCE($2,notes) WHERE id=$3 RETURNING *",
    [req.body.status,req.body.notes||null,req.params.id]);
  res.json(r[0]);
});
app.post("/api/sync",auth,async(req,res)=>{
  const results=[];
  for(const a of (req.body.actions||[])){
    try{
      if(a.type==="gps" && req.user.role==="Driver"){
        await q("INSERT INTO gps_points(trip_id,driver_id,lat,lng,accuracy) VALUES($1,$2,$3,$4,$5)",
          [a.tripId,req.user.id,a.lat,a.lng,a.accuracy||null]);
        await q("UPDATE trips SET current_lat=$1,current_lng=$2,updated_at=NOW() WHERE id=$3",
          [a.lat,a.lng,a.tripId]);
      } else if(a.type==="status"){
        const t=(await q("SELECT * FROM trips WHERE id=$1",[a.tripId]))[0];
        if(t && (req.user.role!=="Driver" || t.driver_id===req.user.id))
          await q("UPDATE trips SET status=$1,updated_at=NOW() WHERE id=$2",[a.status,a.tripId]);
      } else if(a.type==="stop"){
        await q("UPDATE trip_stops SET status=$1,arrived_at=CASE WHEN $1='Arrived' THEN NOW() ELSE arrived_at END,delivered_at=CASE WHEN $1='Delivered' THEN NOW() ELSE delivered_at END WHERE id=$2",
          [a.status,a.stopId]);
      }
      results.push({id:a.id,ok:true});
    }catch(e){results.push({id:a.id,ok:false,error:e.message});}
  }
  res.json({results});
});


// V12: order workflow, automatic trip creation and driver time events
app.get('/api/orders', auth, async (req,res) => {
  try {
    const { rows } = await pool.query(`
      SELECT o.*, c.company AS customer_name
      FROM orders o LEFT JOIN customers c ON c.id=o.customer_id
      ORDER BY o.created_at DESC
    `);
    res.json(rows);
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.post('/api/orders', auth, async (req,res) => {
  try {
    const { customer_id, reference, pickup_address, pickup_city, delivery_address, delivery_city,
            weight_kg, pieces, price_net } = req.body;
    const weight = Number(weight_kg || 0);
    if (weight < 0 || weight > 1000) return res.status(400).json({error:'Gewicht muss zwischen 0 und 1000 KG liegen.'});
    if (!delivery_address) return res.status(400).json({error:'Lieferadresse fehlt.'});
    const { rows } = await pool.query(`
      INSERT INTO orders(customer_id,reference,pickup_address,pickup_city,delivery_address,delivery_city,weight_kg,pieces,price_net)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *
    `,[customer_id||null,reference||null,pickup_address||null,pickup_city||null,delivery_address,delivery_city||null,weight,Number(pieces||1),Number(price_net||0)]);
    res.status(201).json(rows[0]);
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.patch('/api/orders/:id', auth, async (req,res) => {
  try {
    const allowed = [
      'reference','customer_id','pickup_address','pickup_city','delivery_address','delivery_city',
      'weight_kg','pieces','customer_reference','priority','requested_date','time_window_start','time_window_end',
      'estimated_service_min','price_net','status','planned_trip_id','dispatch_note','dispatch_position','assigned_trip_id'
    ];
    const fields = Object.keys(req.body).filter(k=>allowed.includes(k));
    if (!fields.length) return res.status(400).json({error:'Keine gültigen Felder.'});
    const vals = fields.map(k=>req.body[k]);
    vals.push(req.params.id);
    const set = fields.map((k,i)=>`${k}=$${i+1}`).join(',');
    const { rows } = await pool.query(`UPDATE orders SET ${set}, updated_at=NOW() WHERE id=$${vals.length} RETURNING *`, vals);
    if(!rows[0]) return res.status(404).json({error:'Auftrag nicht gefunden.'});
    res.json(rows[0]);
  } catch(e) { res.status(500).json({error:e.message}); }
});

// V194: Auftrag 360 Detail- und Bearbeitungsansicht
app.get('/api/orders/:id/360', auth, async (req,res) => {
  try {
    const order = (await q(`select o.*,c.company customer_company,c.address customer_address,c.city customer_city,c.email customer_email,c.phone customer_phone
      from orders o left join customers c on c.id=o.customer_id where o.id=$1`,[req.params.id]))[0];
    if(!order) return res.status(404).json({error:'Auftrag nicht gefunden.'});
    let trip=null, stops=[];
    const tripId=order.planned_trip_id || order.assigned_trip_id;
    if(tripId){
      trip=(await q(`select t.*,u.name driver_name,v.name vehicle_name,v.plate vehicle_plate
        from trips t left join users u on u.id=t.driver_id left join vehicles v on v.id=t.vehicle_id where t.id=$1`,[tripId]))[0]||null;
      if(trip) stops=await q(`select * from trip_stops where trip_id=$1 order by coalesce(planned_sequence,stop_order),stop_order`,[trip.id]);
    }
    const invoices=await q(`select id,invoice_number,issue_date,due_date,net,vat_rate,vat,gross,status from invoices where customer_id=$1 order by issue_date desc limit 25`,[order.customer_id]);
    res.json({order,trip,stops,invoices});
  } catch(e){res.status(500).json({error:e.message})}
});

app.post('/api/orders/create-trip', auth, async (req,res) => {
  try {
    const { order_ids=[], driver_id=null, vehicle_id=null } = req.body;
    if (!Array.isArray(order_ids) || !order_ids.length) return res.status(400).json({error:'Keine Aufträge ausgewählt.'});
    const { rows: orders } = await pool.query(`SELECT * FROM orders WHERE id = ANY($1::int[]) ORDER BY id`, [order_ids]);
    if (orders.length !== order_ids.length) return res.status(400).json({error:'Mindestens ein Auftrag wurde nicht gefunden.'});
    const total = orders.reduce((a,o)=>a+Number(o.weight_kg||0),0);
    if (total > 1000) return res.status(400).json({error:`Gesamtgewicht ${total.toFixed(1)} KG überschreitet 1000 KG.`});
    const totalPrice = orders.reduce((a,o)=>a+Number(o.price_net||0),0);
    const { rows: tripRows } = await pool.query(`
      INSERT INTO trips(driver_id, vehicle_id, status, weight_kg, price_net, notes)
      VALUES($1,$2,'Planned',$3,$4,$5) RETURNING *
    `,[driver_id||null,vehicle_id||null,total,totalPrice,`V12 automatisch aus ${orders.length} Auftrag/Aufträgen erstellt`]);
    const trip = tripRows[0];
    let seq=1;
    for (const o of orders) {
      await pool.query(`
        INSERT INTO trip_stops(trip_id, stop_order, address, city, status)
        VALUES($1,$2,$3,$4,'Pending')
      `,[trip.id,seq++,o.delivery_address,o.delivery_city||null]);
      await pool.query(`UPDATE orders SET assigned_trip_id=$1,status='planned',updated_at=NOW() WHERE id=$2`,[trip.id,o.id]);
    }
    res.status(201).json({trip_id:trip.id, trip, order_count:orders.length});
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.post('/api/trips/:id/time', auth, async (req,res) => {
  try {
    const { event_type, stop_id=null, note=null } = req.body;
    const allowed = ['shift_start','arrived','departed','trip_start','trip_end'];
    if (!allowed.includes(event_type)) return res.status(400).json({error:'Ungültiger Zeitstempel.'});
    const { rows } = await pool.query(`
      INSERT INTO driver_time_events(trip_id,stop_id,driver_id,event_type,note)
      VALUES($1,$2,$3,$4,$5) RETURNING *
    `,[req.params.id,stop_id,req.user.id,event_type,note]);
    if (event_type==='arrived' && stop_id) await pool.query(`UPDATE trip_stops SET arrived_at=NOW(),status='Arrived' WHERE id=$1`,[stop_id]);
    if (event_type==='departed' && stop_id) await pool.query(`UPDATE trip_stops SET departed_at=NOW() WHERE id=$1`,[stop_id]);
    res.status(201).json(rows[0]);
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.get('/api/trips/:id/time', auth, async (req,res) => {
  try {
    const { rows } = await pool.query(`SELECT * FROM driver_time_events WHERE trip_id=$1 ORDER BY event_at`,[req.params.id]);
    res.json(rows);
  } catch(e) { res.status(500).json({error:e.message}); }
});



// V13: dispatch board and stop-level proof/status actions
app.get('/api/dispatch/board', auth, async (req,res) => {
  try {
    const { rows } = await pool.query(`
      SELECT
        t.id, t.status, t.priority, t.weight_kg, t.price_net, t.planned_start_at, t.board_note,
        t.driver_id, u.name AS driver_name,
        t.vehicle_id, v.plate AS vehicle_plate,
        COUNT(ts.id)::int AS stop_count,
        COUNT(*) FILTER (WHERE ts.status='Delivered')::int AS delivered_count
      FROM trips t
      LEFT JOIN users u ON u.id=t.driver_id
      LEFT JOIN vehicles v ON v.id=t.vehicle_id
      LEFT JOIN trip_stops ts ON ts.trip_id=t.id
      GROUP BY t.id,u.name,v.plate
      ORDER BY
        CASE t.status
          WHEN 'Planned' THEN 1
          WHEN 'In Transit' THEN 2
          WHEN 'Delivered' THEN 3
          ELSE 4
        END,
        CASE t.priority WHEN 'urgent' THEN 1 WHEN 'high' THEN 2 ELSE 3 END,
        t.id DESC
    `);
    res.json(rows);
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.patch('/api/trips/:id/dispatch', auth, async (req,res) => {
  try {
    const { driver_id=null, vehicle_id=null, status=null, priority=null, planned_start_at=null, board_note=null } = req.body;
    const { rows } = await pool.query(`
      UPDATE trips SET
        driver_id=COALESCE($1,driver_id),
        vehicle_id=COALESCE($2,vehicle_id),
        status=COALESCE($3,status),
        priority=COALESCE($4,priority),
        planned_start_at=COALESCE($5,planned_start_at),
        board_note=COALESCE($6,board_note)
      WHERE id=$7 RETURNING *
    `,[driver_id,vehicle_id,status,priority,planned_start_at,board_note,req.params.id]);
    res.json(rows[0]);
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.get('/api/trips/:id/stops', auth, async (req,res) => {
  try {
    const { rows } = await pool.query(`
      SELECT * FROM trip_stops WHERE trip_id=$1 ORDER BY stop_order,id
    `,[req.params.id]);
    res.json(rows);
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.patch('/api/stops/:id', auth, async (req,res) => {
  try {
    const { status, stop_order, proof_note, delivered_weight_kg, delivered_pieces, signature_data, photo_data } = req.body;
    const { rows } = await pool.query(`
      UPDATE trip_stops SET
        status=COALESCE($1,status),
        stop_order=COALESCE($2,stop_order),
        proof_note=COALESCE($3,proof_note),
        delivered_weight_kg=COALESCE($4,delivered_weight_kg),
        delivered_pieces=COALESCE($5,delivered_pieces),
        signature_data=COALESCE($6,signature_data),
        photo_data=COALESCE($7,photo_data),
        delivered_at=CASE WHEN $1 IN ('Delivered','delivered') THEN COALESCE(delivered_at,NOW()) ELSE delivered_at END
      WHERE id=$8 RETURNING *
    `,[status||null,stop_order??null,proof_note||null,
       delivered_weight_kg??null,delivered_pieces??null,
       signature_data||null,photo_data||null,req.params.id]);
    res.json(rows[0]);
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.post('/api/trips/:id/reorder-stops', auth, async (req,res) => {
  try {
    const ids = Array.isArray(req.body.stop_ids) ? req.body.stop_ids : [];
    await pool.query('BEGIN');
    for (let i=0;i<ids.length;i++) {
      await pool.query('UPDATE trip_stops SET stop_order=$1 WHERE id=$2 AND trip_id=$3',[i+1,ids[i],req.params.id]);
    }
    await pool.query('COMMIT');
    const { rows } = await pool.query('SELECT * FROM trip_stops WHERE trip_id=$1 ORDER BY stop_order,id',[req.params.id]);
    res.json(rows);
  } catch(e) {
    try { await pool.query('ROLLBACK'); } catch(_){}
    res.status(500).json({error:e.message});
  }
});



// V14: realtime event stream + role-aware notification center
const v14Clients = new Set();
function v14Broadcast(event) {
  const payload = `data: ${JSON.stringify(event)}\n\n`;
  for (const res of v14Clients) { try { res.write(payload); } catch (_) {} }
}
async function v14Notify(userIds, type, title, message, entityType=null, entityId=null) {
  const ids=[...new Set((userIds||[]).filter(Boolean))];
  for (const uid of ids) {
    await pool.query(
      `INSERT INTO notifications(user_id,type,title,message,entity_type,entity_id) VALUES($1,$2,$3,$4,$5,$6)`,
      [uid,type,title,message,entityType,entityId]
    );
  }
  v14Broadcast({type:'notification',user_ids:ids,title,message,entity_type:entityType,entity_id:entityId});
}

app.get('/api/events', auth, (req,res) => {
  res.setHeader('Content-Type','text/event-stream');
  res.setHeader('Cache-Control','no-cache');
  res.setHeader('Connection','keep-alive');
  res.flushHeaders?.();
  res.write(`data: ${JSON.stringify({type:'connected',at:new Date().toISOString()})}\n\n`);
  v14Clients.add(res);
  req.on('close',()=>v14Clients.delete(res));
});

app.get('/api/notifications', auth, async (req,res) => {
  try {
    const {rows}=await pool.query(
      `SELECT * FROM notifications WHERE user_id=$1 ORDER BY created_at DESC LIMIT 50`,
      [req.user.id]
    );
    res.json(rows);
  } catch(e){res.status(500).json({error:e.message});}
});

app.post('/api/notifications/:id/read', auth, async (req,res) => {
  try {
    const {rows}=await pool.query(
      `UPDATE notifications SET read_at=NOW() WHERE id=$1 AND user_id=$2 RETURNING *`,
      [req.params.id,req.user.id]
    );
    res.json(rows[0]||null);
  } catch(e){res.status(500).json({error:e.message});}
});

// Notify relevant roles whenever dispatch assignment changes.
app.post('/api/trips/:id/dispatch-notify', auth, async (req,res)=>{
  try{
    const {rows}=await pool.query(
      `SELECT t.id,t.driver_id,t.vehicle_id,u.name AS driver_name,v.plate
       FROM trips t LEFT JOIN users u ON u.id=t.driver_id LEFT JOIN vehicles v ON v.id=t.vehicle_id
       WHERE t.id=$1`,[req.params.id]);
    if(!rows[0])return res.status(404).json({error:'Tour nicht gefunden'});
    const q=await pool.query(`SELECT id FROM users WHERE role IN ('Admin','Dispatcher','Driver')`);
    const ids=q.rows.map(x=>x.id);
    await v14Notify(ids,'dispatch','Tour aktualisiert',`Tour #${rows[0].id} wurde disponiert.`,'trip',rows[0].id);
    res.json({ok:true});
  }catch(e){res.status(500).json({error:e.message});}
});



// V15: complete delivery chain: stop proof -> DDT -> invoice
async function v15TripComplete(tripId) {
  const t=(await q("select * from trips where id=$1",[tripId]))[0];
  if(!t) return null;
  const stops=await q("select * from trip_stops where trip_id=$1 order by stop_order",[tripId]);
  const complete=stops.length>0 && stops.every(x=>String(x.status||'').toLowerCase()==='delivered' || x.delivered_at);
  if(!complete) return {complete:false};
  if(String(t.status)!=='Delivered'){
    await q("update trips set status='Delivered',updated_at=now() where id=$1",[tripId]);
    t.status='Delivered';
  }
  let d=(await q("select * from delivery_documents where trip_id=$1",[tripId]))[0];
  if(!d){
    const n=await q("select 'DDT-'||extract(year from current_date)::int||'-'||lpad((coalesce(max(cast(split_part(document_number,'-',3) as int)),0)+1)::text,4,'0') n from delivery_documents");
    d=(await q("insert into delivery_documents(trip_id,document_number,proof_complete) values($1,$2,true) returning *",[tripId,n[0].n]))[0];
  } else if(!d.proof_complete) {
    d=(await q("update delivery_documents set proof_complete=true,status='Completed' where id=$1 returning *",[d.id]))[0];
  }
  if(Number(t.price_net)>0){
    await autoInvoice({user:{id:null,name:'System',role:'Admin'}},t);
  }
  return {complete:true,deliveryDocument:d,trip:t};
}

app.post("/api/stops/:id/proof",auth,roles("Admin","Dispatcher","Driver"),async(req,res)=>{
  try{
    const st=(await q("select * from trip_stops where id=$1",[req.params.id]))[0];
    if(!st)return res.status(404).json({error:"Stop not found"});
    if(req.user.role==="Driver"){
      const own=(await q("select id from trips where id=$1 and driver_id=$2",[st.trip_id,req.user.id]))[0];
      if(!own)return res.status(403).json({error:"Not your trip"});
    }
    const weight=req.body.deliveredWeightKg==null?null:+req.body.deliveredWeightKg;
    if(weight!=null && (weight<0 || weight>1000)) return res.status(400).json({error:"Delivered KG must be between 0 and 1000"});
    const r=(await q(`
      update trip_stops set
        status='Delivered',
        delivered_at=coalesce(delivered_at,now()),
        delivered_weight_kg=coalesce($1,delivered_weight_kg),
        delivered_pieces=coalesce($2,delivered_pieces),
        proof_note=coalesce($3,proof_note),
        signature_data=coalesce($4,signature_data),
        photo_data=coalesce($5,photo_data)
      where id=$6 returning *
    `,[weight,req.body.deliveredPieces==null?null:+req.body.deliveredPieces,req.body.note||null,
       req.body.signatureData||null,req.body.photoData||null,req.params.id]))[0];
    await audit(req,"STOP_DELIVERED","Stop "+req.params.id+" / Trip "+r.trip_id);
    const chain=await v15TripComplete(r.trip_id);
    res.json({stop:r,chain});
  }catch(e){res.status(500).json({error:e.message});}
});

app.get("/api/documents/delivery-note/:id",auth,async(req,res)=>{
  const t=(await q(`select t.*,c.company,c.address,c.city,c.vat_id,d.document_number,d.issued_at
                    from trips t join customers c on c.id=t.customer_id
                    left join delivery_documents d on d.trip_id=t.id
                    where t.id=$1`,[req.params.id]))[0];
  if(!t)return res.status(404).send("Not found");
  const st=await q("select * from trip_stops where trip_id=$1 order by stop_order",[req.params.id]);
  const rows=st.map(x=>`<tr><td>${x.stop_order}</td><td>${x.address||''} ${x.customer_name||''}</td><td>${x.status}</td><td>${x.delivered_at?v189DateOnly(x.delivered_at):'—'}</td></tr>`).join("");
  res.type("html").send(doc("DDT "+(t.document_number||t.trip_number),`
    <div class="top"><div><b>Emergency Delivery</b><p>Documento di trasporto · Italia</p></div>
    <div class="right">DDT<h1>${t.document_number||'—'}</h1>${t.issued_at?new Date(t.issued_at).toISOString().slice(0,10):new Date().toISOString().slice(0,10)}</div></div>
    <div class="grid"><div class="card"><small>CLIENTE</small><b>${t.company}</b><br>${t.address||''}<br>${t.city||''}<br>${t.vat_id||''}</div>
    <div class="card"><small>TOUR</small>${t.trip_number}<br>${Number(t.weight_kg||0).toFixed(1)} KG · ${t.pieces||0} Stk.<br>Status: ${t.status}</div></div>
    <table><tr><th>#</th><th>Destinazione</th><th>Status</th><th>Consegnato</th></tr>${rows}</table>
    <p><b>Firma / Prova di consegna:</b> ${st.every(x=>x.signature_data||x.photo_data)?'presente':'da completare'}</p>`));
});

app.get("/api/permissions",auth,async(req,res)=>{
  const map={
    Admin:["dashboard","dispatch","drivers","vehicles","customers","orders","invoices","documents","audit","settings"],
    Dispatcher:["dashboard","dispatch","drivers","vehicles","customers","orders","documents"],
    Driver:["dashboard","my_trips","navigation","delivery_proof","gps"],
    Accounting:["dashboard","customers","invoices","documents","audit"]
  };
  res.json({role:req.user.role,permissions:map[req.user.role]||[]});
});



// V16: mobile driver workflow
app.get("/api/driver/dashboard",auth,roles("Driver"),async(req,res)=>{
  try{
    const trips=await q(`
      select t.*, v.name as vehicle_name, v.plate as vehicle_plate,
        c.company as customer_company
      from trips t
      left join vehicles v on v.id=t.vehicle_id
      left join customers c on c.id=t.customer_id
      where t.driver_id=$1 and t.status <> 'Delivered'
      order by
        case when t.status='In Transit' then 1 when t.status='Planned' then 2 else 3 end,
        coalesce(t.planned_start_at,t.created_at), t.created_at
    `,[req.user.id]);
    for(const t of trips){
      t.stops=await q("select * from trip_stops where trip_id=$1 order by stop_order",[t.id]);
    }
    res.json({driver:req.user,trips});
  }catch(e){res.status(500).json({error:e.message});}
});

app.post("/api/driver/trips/:id/start",auth,roles("Driver"),async(req,res)=>{
  try{
    const t=(await q("select * from trips where id=$1 and driver_id=$2",[req.params.id,req.user.id]))[0];
    if(!t)return res.status(404).json({error:"Tour nicht gefunden oder nicht zugewiesen."});
    const r=(await q("update trips set status='In Transit',updated_at=now() where id=$1 returning *",[t.id]))[0];
    await q(`insert into driver_time_events(trip_id,driver_id,event_type) values($1,$2,'trip_start')`,[t.id,req.user.id]).catch(()=>{});
    await audit(req,"DRIVER_TRIP_STARTED",r.trip_number);
    v14Broadcast({type:"trip_status",trip_id:r.id,status:r.status});
    res.json(r);
  }catch(e){res.status(500).json({error:e.message});}
});

app.post("/api/driver/stops/:id/arrive",auth,roles("Driver"),async(req,res)=>{
  try{
    const st=(await q(`select s.*,t.driver_id from trip_stops s join trips t on t.id=s.trip_id where s.id=$1`,[req.params.id]))[0];
    if(!st)return res.status(404).json({error:"Stop nicht gefunden"});
    if(st.driver_id!==req.user.id)return res.status(403).json({error:"Stop gehört nicht zu deiner Tour"});
    const r=(await q("update trip_stops set status='Arrived',arrived_at=coalesce(arrived_at,now()) where id=$1 returning *",[st.id]))[0];
    await q(`insert into driver_time_events(trip_id,stop_id,driver_id,event_type) values($1,$2,$3,'arrived')`,[st.trip_id,st.id,req.user.id]).catch(()=>{});
    v14Broadcast({type:"stop_status",stop_id:r.id,trip_id:r.trip_id,status:r.status});
    res.json(r);
  }catch(e){res.status(500).json({error:e.message});}
});

app.post("/api/driver/stops/:id/depart",auth,roles("Driver"),async(req,res)=>{
  try{
    const st=(await q(`select s.*,t.driver_id from trip_stops s join trips t on t.id=s.trip_id where s.id=$1`,[req.params.id]))[0];
    if(!st)return res.status(404).json({error:"Stop nicht gefunden"});
    if(st.driver_id!==req.user.id)return res.status(403).json({error:"Stop gehört nicht zu deiner Tour"});
    const r=(await q("update trip_stops set departed_at=coalesce(departed_at,now()) where id=$1 returning *",[st.id]))[0];
    await q(`insert into driver_time_events(trip_id,stop_id,driver_id,event_type) values($1,$2,$3,'departed')`,[st.trip_id,st.id,req.user.id]).catch(()=>{});
    v14Broadcast({type:"stop_departed",stop_id:r.id,trip_id:r.trip_id});
    res.json(r);
  }catch(e){res.status(500).json({error:e.message});}
});

app.post("/api/driver/gps",auth,roles("Driver"),async(req,res)=>{
  const t=(await q("select id from trips where id=$1 and driver_id=$2",[req.body.tripId,req.user.id]))[0];
  if(!t)return res.status(404).json({error:"Tour nicht gefunden"});
  const lat=Number(req.body.lat),lng=Number(req.body.lng);
  if(!Number.isFinite(lat)||!Number.isFinite(lng))return res.status(400).json({error:"Ungültige GPS-Daten"});
  const r=await q("insert into gps_points(trip_id,driver_id,lat,lng,accuracy) values($1,$2,$3,$4,$5) returning *",[t.id,req.user.id,lat,lng,req.body.accuracy||null]);
  await q("update trips set current_lat=$1,current_lng=$2,updated_at=now() where id=$3",[lat,lng,t.id]);
  v14Broadcast({type:"gps",trip_id:t.id,lat,lng});
  res.json(r[0]);
});



// V17: mobile proof capture + live fleet map data
app.get("/api/fleet/live",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const rows=await q(`
      select t.id,t.trip_number,t.status,t.current_lat,t.current_lng,t.updated_at,
             u.name as driver_name,v.name as vehicle_name,v.plate as vehicle_plate
      from trips t
      left join users u on u.id=t.driver_id
      left join vehicles v on v.id=t.vehicle_id
      where t.status <> 'Delivered' and t.current_lat is not null and t.current_lng is not null
      order by t.updated_at desc
    `);
    res.json(rows);
  }catch(e){res.status(500).json({error:e.message});}
});

app.post("/api/driver/stops/:id/proof-capture",auth,roles("Driver"),async(req,res)=>{
  try{
    const st=(await q(`select s.*,t.driver_id from trip_stops s join trips t on t.id=s.trip_id where s.id=$1`,[req.params.id]))[0];
    if(!st)return res.status(404).json({error:"Stop nicht gefunden"});
    if(st.driver_id!==req.user.id)return res.status(403).json({error:"Nicht deine Tour"});
    const signature=req.body.signatureData||null;
    const photo=req.body.photoData||null;
    if(signature && signature.length>8_000_000) return res.status(413).json({error:"Unterschrift zu groß"});
    if(photo && photo.length>12_000_000) return res.status(413).json({error:"Foto zu groß"});
    const r=(await q(`
      update trip_stops set
        signature_data=coalesce($1,signature_data),
        photo_data=coalesce($2,photo_data),
        proof_note=coalesce($3,proof_note)
      where id=$4 returning *
    `,[signature,photo,req.body.note||null,st.id]))[0];
    await audit(req,"PROOF_CAPTURED","Stop "+st.id);
    res.json({ok:true,stop:r});
  }catch(e){res.status(500).json({error:e.message});}
});



// V18: live fleet map + driver status / ETA foundation
app.get("/api/fleet/status",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const rows=await q(`
      select t.id,t.trip_number,t.status,t.current_lat,t.current_lng,t.updated_at,
             u.name as driver_name,u.id as driver_id,
             v.name as vehicle_name,v.plate as vehicle_plate,
             (select count(*) from trip_stops s where s.trip_id=t.id)::int as stop_count,
             (select count(*) from trip_stops s where s.trip_id=t.id and (s.status='Delivered' or s.delivered_at is not null))::int as delivered_count,
             (select min(s.stop_order) from trip_stops s where s.trip_id=t.id and s.status<>'Delivered') as next_stop_order
      from trips t
      left join users u on u.id=t.driver_id
      left join vehicles v on v.id=t.vehicle_id
      where t.status <> 'Delivered'
      order by t.updated_at desc
    `);
    res.json(rows.map(x=>({
      ...x,
      progress:x.stop_count?Math.round((x.delivered_count/x.stop_count)*100):0,
      stale_seconds:x.updated_at?Math.max(0,Math.floor((Date.now()-new Date(x.updated_at).getTime())/1000)):null
    })));
  }catch(e){res.status(500).json({error:e.message});}
});

app.get("/api/fleet/trip/:id/next-stop",auth,roles("Admin","Dispatcher","Driver"),async(req,res)=>{
  try{
    const t=(await q("select * from trips where id=$1",[req.params.id]))[0];
    if(!t)return res.status(404).json({error:"Tour nicht gefunden"});
    if(req.user.role==="Driver" && t.driver_id!==req.user.id)return res.status(403).json({error:"Nicht deine Tour"});
    const st=(await q(`select * from trip_stops where trip_id=$1 and status<>'Delivered' order by stop_order limit 1`,[t.id]))[0];
    res.json(st||null);
  }catch(e){res.status(500).json({error:e.message});}
});



// V19: route/ETA/geofence foundation
app.get("/api/fleet/trip/:id/route",auth,roles("Admin","Dispatcher","Driver"),async(req,res)=>{
  try{
    const t=(await q("select * from trips where id=$1",[req.params.id]))[0];
    if(!t)return res.status(404).json({error:"Tour nicht gefunden"});
    if(req.user.role==="Driver" && t.driver_id!==req.user.id)return res.status(403).json({error:"Nicht deine Tour"});
    const stops=await q("select * from trip_stops where trip_id=$1 order by stop_order",[t.id]);
    const coords=stops.map(x=>({id:x.id,order:x.stop_order,address:x.address,city:x.city||'',lat:x.lat||null,lng:x.lng||null,status:x.status}));
    const first=coords[0], last=coords[coords.length-1];
    const waypoints=coords.slice(1,-1).filter(x=>x.lat!=null&&x.lng!=null).map(x=>`${x.lat},${x.lng}`).join("|");
    const mapsUrl=first&&last
      ? `https://www.google.com/maps/dir/?api=1&origin=${encodeURIComponent(first.address+' '+first.city)}&destination=${encodeURIComponent(last.address+' '+last.city)}${waypoints?'&waypoints='+encodeURIComponent(waypoints):''}`
      : null;
    res.json({trip:t,stops:coords,mapsUrl});
  }catch(e){res.status(500).json({error:e.message});}
});

app.post("/api/driver/stops/:id/geofence-check",auth,roles("Driver"),async(req,res)=>{
  try{
    const st=(await q(`select s.*,t.driver_id from trip_stops s join trips t on t.id=s.trip_id where s.id=$1`,[req.params.id]))[0];
    if(!st)return res.status(404).json({error:"Stop nicht gefunden"});
    if(st.driver_id!==req.user.id)return res.status(403).json({error:"Nicht deine Tour"});
    const lat=Number(req.body.lat),lng=Number(req.body.lng),targetLat=Number(req.body.targetLat),targetLng=Number(req.body.targetLng);
    if(![lat,lng,targetLat,targetLng].every(Number.isFinite))return res.status(400).json({error:"Ungültige Koordinaten"});
    const R=6371000,rad=x=>x*Math.PI/180;
    const dLat=rad(targetLat-lat),dLng=rad(targetLng-lng);
    const a=Math.sin(dLat/2)**2+Math.cos(rad(lat))*Math.cos(rad(targetLat))*Math.sin(dLng/2)**2;
    const distance=Math.round(2*R*Math.asin(Math.sqrt(a)));
    const radius=Math.max(50,Number(req.body.radius||150));
    res.json({inside:distance<=radius,distance_m:distance,radius_m:radius});
  }catch(e){res.status(500).json({error:e.message});}
});



// V20: ETA engine, geofence auto-arrival and next-stop notifications
function v20Haversine(aLat,aLng,bLat,bLng){
  const R=6371000,rad=x=>x*Math.PI/180;
  const dLat=rad(bLat-aLat),dLng=rad(bLng-aLng);
  const aa=Math.sin(dLat/2)**2+Math.cos(rad(aLat))*Math.cos(rad(bLat))*Math.sin(dLng/2)**2;
  return 2*R*Math.asin(Math.sqrt(aa));
}
app.post("/api/fleet/trip/:id/eta",auth,roles("Admin","Dispatcher","Driver"),async(req,res)=>{
  try{
    const t=(await q("select * from trips where id=$1",[req.params.id]))[0];
    if(!t)return res.status(404).json({error:"Tour nicht gefunden"});
    if(req.user.role==="Driver" && t.driver_id!==req.user.id)return res.status(403).json({error:"Nicht deine Tour"});
    const stop=(await q("select * from trip_stops where trip_id=$1 and status<>'Delivered' order by stop_order limit 1",[t.id]))[0];
    if(!stop)return res.json({trip_id:t.id,next_stop:null,eta_at:null,eta_minutes:0});
    const lat=Number(req.body.lat??t.current_lat),lng=Number(req.body.lng??t.current_lng);
    const targetLat=Number(stop.lat),targetLng=Number(stop.lng);
    let minutes=Number(req.body.etaMinutes);
    if(!Number.isFinite(minutes)){
      if([lat,lng,targetLat,targetLng].every(Number.isFinite)){
        const km=v20Haversine(lat,lng,targetLat,targetLng)/1000;
        minutes=Math.max(1,Math.ceil((km/45)*60));
      } else minutes=null;
    }
    const eta=minutes==null?null:new Date(Date.now()+minutes*60000);
    await q("update trips set eta_at=$1,eta_minutes=$2,eta_updated_at=now(),updated_at=now() where id=$3",[eta,minutes,t.id]);
    await q("update trip_stops set eta_at=$1,eta_minutes=$2 where id=$3",[eta,minutes,stop.id]);
    v14Broadcast({type:"eta",trip_id:t.id,stop_id:stop.id,eta_at:eta,eta_minutes:minutes});
    res.json({trip_id:t.id,next_stop:stop,eta_at:eta,eta_minutes:minutes});
  }catch(e){res.status(500).json({error:e.message});}
});

app.post("/api/driver/stops/:id/auto-arrival",auth,roles("Driver"),async(req,res)=>{
  try{
    const st=(await q(`select s.*,t.driver_id,t.arrival_radius_m from trip_stops s join trips t on t.id=s.trip_id where s.id=$1`,[req.params.id]))[0];
    if(!st)return res.status(404).json({error:"Stop nicht gefunden"});
    if(st.driver_id!==req.user.id)return res.status(403).json({error:"Nicht deine Tour"});
    const lat=Number(req.body.lat),lng=Number(req.body.lng),targetLat=Number(st.lat),targetLng=Number(st.lng);
    if(![lat,lng,targetLat,targetLng].every(Number.isFinite))return res.status(400).json({error:"Stop benötigt GPS-Koordinaten"});
    const distance=Math.round(v20Haversine(lat,lng,targetLat,targetLng)),radius=Math.max(50,Number(st.arrival_radius_m||150));
    if(distance<=radius && st.status!=="Delivered"){
      const r=(await q("update trip_stops set status='Arrived',arrived_at=coalesce(arrived_at,now()),geofence_arrived_at=coalesce(geofence_arrived_at,now()) where id=$1 returning *",[st.id]))[0];
      await q(`insert into driver_time_events(trip_id,stop_id,driver_id,event_type,note) values($1,$2,$3,'arrived','Geofence')`,[st.trip_id,st.id,req.user.id]).catch(()=>{});
      const users=await q(`select id from users where role in ('Admin','Dispatcher')`);
      await v14Notify(users.rows.map(x=>x.id),'arrival','Fahrer angekommen',`Tour ${st.trip_id}: Fahrer ist am nächsten Stopp angekommen.`,'trip',st.trip_id);
      v14Broadcast({type:"auto_arrival",trip_id:st.trip_id,stop_id:st.id,distance_m:distance});
      return res.json({arrived:true,distance_m:distance,radius_m:radius,stop:r});
    }
    res.json({arrived:false,distance_m:distance,radius_m:radius,stop:st});
  }catch(e){res.status(500).json({error:e.message});}
});



// V21: order pricing, recurring orders and day planning
app.post("/api/pricing/calculate",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const customerId=req.body.customerId||null, kg=Number(req.body.weightKg||0);
    const urgent=req.body.urgent===true;
    if(kg<0||kg>1000)return res.status(400).json({error:"Gewicht muss zwischen 0 und 1000 KG liegen."});
    let rule=(await q(`select * from order_pricing where active=true and (customer_id=$1 or customer_id is null)
      and min_weight_kg <= $2 and max_weight_kg >= $2
      order by case when customer_id is null then 1 else 0 end, min_weight_kg desc limit 1`,[customerId,kg]))[0];
    if(!rule)return res.json({net:0,rule:null});
    const net=+(Number(rule.base_price)+kg*Number(rule.price_per_kg)+(urgent?Number(rule.urgent_surcharge):0)).toFixed(2);
    res.json({net,rule,urgent});
  }catch(e){res.status(500).json({error:e.message});}
});

app.post("/api/pricing/rules",auth,roles("Admin","Accounting"),async(req,res)=>{
  try{
    const r=(await q(`insert into order_pricing(customer_id,min_weight_kg,max_weight_kg,base_price,price_per_kg,urgent_surcharge)
      values($1,$2,$3,$4,$5,$6) returning *`,
      [req.body.customerId||null,Number(req.body.minWeightKg||0),Number(req.body.maxWeightKg||1000),
       Number(req.body.basePrice||0),Number(req.body.pricePerKg||0),Number(req.body.urgentSurcharge||0)]))[0];
    await audit(req,"PRICING_RULE_CREATED",r.id);res.json(r);
  }catch(e){res.status(500).json({error:e.message});}
});

app.get("/api/recurring-orders",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{res.json(await q(`select r.*,c.company as customer_company from recurring_orders r left join customers c on c.id=r.customer_id order by active desc,next_run_date`));}
  catch(e){res.status(500).json({error:e.message});}
});

app.post("/api/recurring-orders",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const w=Number(req.body.weightKg||0);if(w>1000)return res.status(400).json({error:"Maximum 1,000 KG"});
    const r=(await q(`insert into recurring_orders(customer_id,reference,pickup_address,pickup_city,delivery_address,delivery_city,weight_kg,pieces,price_net,frequency,weekday,next_run_date)
      values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) returning *`,
      [req.body.customerId||null,req.body.reference||null,req.body.pickupAddress||null,req.body.pickupCity||null,
       req.body.deliveryAddress,req.body.deliveryCity||null,w,Number(req.body.pieces||1),Number(req.body.priceNet||0),
       req.body.frequency||'weekly',req.body.weekday==null?null:Number(req.body.weekday),req.body.nextRunDate||null]))[0];
    await audit(req,"RECURRING_ORDER_CREATED",r.id);res.json(r);
  }catch(e){res.status(500).json({error:e.message});}
});

app.post("/api/planning/day",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const date=req.body.date||new Date().toISOString().slice(0,10);
    const jobs=await q(`select * from orders where status in ('new','planned') and (assigned_trip_id is null or status='new') order by
      case when status='new' then 0 else 1 end, delivery_city, id`);
    const totalWeight=jobs.reduce((a,x)=>a+Number(x.weight_kg||0),0);
    const tours=[];
    let current=[],sum=0;
    for(const j of jobs){
      const w=Number(j.weight_kg||0);
      if(current.length && sum+w>1000){tours.push(current);current=[];sum=0;}
      current.push(j);sum+=w;
    }
    if(current.length)tours.push(current);
    res.json({date,order_count:jobs.length,total_weight_kg:+totalWeight.toFixed(2),
      suggested_tours:tours.map((a,i)=>({tour_index:i+1,weight_kg:+a.reduce((x,y)=>x+Number(y.weight_kg||0),0).toFixed(2),
      order_ids:a.map(x=>x.id),cities:[...new Set(a.map(x=>x.delivery_city).filter(Boolean))]}))});
  }catch(e){res.status(500).json({error:e.message});}
});



// V22: two-vehicle daily dispatch board
app.get("/api/planning/board",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const date=req.query.date||new Date().toISOString().slice(0,10);
    const trips=await q(`select t.*,c.company as customer_company,u.name as driver_name,v.name as vehicle_name,v.plate
      from trips t left join customers c on c.id=t.customer_id left join users u on u.id=t.driver_id
      left join vehicles v on v.id=t.vehicle_id
      where t.planning_date=$1 order by coalesce(t.assigned_vehicle_slot,99),coalesce(t.planned_sequence,99),t.created_at`,[date]);
    const open=await q(`select o.*,c.company as customer_company from orders o left join customers c on c.id=o.customer_id
      where o.status in ('new','planned') and o.assigned_trip_id is null order by
      case when o.status='new' then 0 else 1 end, o.delivery_city, o.id`);
    const slots=[1,2].map(slot=>({slot,trips:trips.filter(t=>t.assigned_vehicle_slot===slot)}));
    res.json({date,slots,open_orders:open});
  }catch(e){res.status(500).json({error:e.message});}
});

app.post("/api/planning/assign",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const trip=(await q("select * from trips where id=$1",[req.body.tripId]))[0];
    if(!trip)return res.status(404).json({error:"Tour nicht gefunden"});
    const slot=Number(req.body.vehicleSlot);
    if(![1,2].includes(slot))return res.status(400).json({error:"Nur Transporter 1 oder 2"});
    const plannedDate=req.body.planningDate||new Date().toISOString().slice(0,10);
    const vehicle=(await q("select * from vehicles where active=true order by name limit 2 offset $1",[slot-1]))[0];
    await q(`update trips set planning_date=$1,assigned_vehicle_slot=$2,vehicle_id=coalesce($3,vehicle_id),
      planned_sequence=$4 where id=$5`,[plannedDate,slot,vehicle?.id||null,Number(req.body.sequence||1),trip.id]);
    await audit(req,"PLANNING_ASSIGN",`${trip.trip_number} -> Transporter ${slot}`);
    res.json((await q("select * from trips where id=$1",[trip.id]))[0]);
  }catch(e){res.status(500).json({error:e.message});}
});

app.post("/api/planning/resequence",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const ids=Array.isArray(req.body.tripIds)?req.body.tripIds:[];
    for(let i=0;i<ids.length;i++) await q("update trips set planned_sequence=$1 where id=$2",[i+1,ids[i]]);
    await audit(req,"PLANNING_RESEQUENCE",ids.join(","));
    res.json({ok:true});
  }catch(e){res.status(500).json({error:e.message});}
});

app.post("/api/planning/build",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const date=req.body.date||new Date().toISOString().slice(0,10);
    const orders=await q(`select * from orders where status in ('new','planned') and assigned_trip_id is null
      order by case when status='new' then 0 else 1 end, delivery_city, id`);
    const buckets=[[],[]], weights=[0,0];
    for(const o of orders){
      const w=Number(o.weight_kg||0);
      let slot=weights[0]<=weights[1]?0:1;
      if(weights[slot]+w>1000 && weights[1-slot]+w<=1000) slot=1-slot;
      if(weights[slot]+w>1000) continue;
      buckets[slot].push(o);weights[slot]+=w;
    }
    const created=[];
    for(let slot=0;slot<2;slot++){
      if(!buckets[slot].length) continue;
      const total=buckets[slot].reduce((a,o)=>a+Number(o.weight_kg||0),0);
      const revenue=buckets[slot].reduce((a,o)=>a+Number(o.price_net||0),0);
      const n="TR-"+Date.now().toString().slice(-8)+"-"+(slot+1);
      const trip=(await q(`insert into trips(trip_number,weight_kg,pieces,status,assigned_vehicle_slot,planning_date,planned_sequence,price_net,planned_revenue_net,notes)
        values($1,$2,$3,'Planned',$4,$5,1,$6,$6,'V22 Tagesplanung') returning *`,
        [n,total,buckets[slot].reduce((a,o)=>a+Number(o.pieces||0),0),slot+1,date,revenue]))[0];
      let seq=1;
      for(const o of buckets[slot]){
        await q(`update orders set assigned_trip_id=$1,status='planned' where id=$2`,[trip.id,o.id]);
        await q(`insert into trip_stops(trip_id,stop_order,planned_sequence,address,customer_name) values($1,$2,$3,$4,$5)`,
          [trip.id,seq,seq,o.delivery_address,o.customer_id||null]);
        seq++;
      }
      created.push(trip);
    }
    await audit(req,"PLANNING_BUILD",`${date}: ${created.length} Touren`);
    res.json({date,created});
  }catch(e){res.status(500).json({error:e.message});}
});



// V23: dispatch editing, driver assignment, priority and stop sequencing
app.patch("/api/planning/trips/:id",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const allowed=["assigned_vehicle_slot","driver_id","vehicle_id","priority","dispatcher_note","planned_start_at","planned_sequence"];
    const keys=Object.keys(req.body).filter(k=>allowed.includes(k));
    if(!keys.length)return res.status(400).json({error:"Keine gültigen Felder"});
    const vals=keys.map(k=>req.body[k]);
    const set=keys.map((k,i)=>`${k}=$${i+1}`).join(",");
    vals.push(req.params.id);
    const r=(await q(`update trips set ${set} where id=$${vals.length} returning *`,vals))[0];
    if(!r)return res.status(404).json({error:"Tour nicht gefunden"});
    await audit(req,"PLANNING_TRIP_EDIT",`${r.trip_number}: ${keys.join(",")}`);
    res.json(r);
  }catch(e){res.status(500).json({error:e.message});}
});

app.patch("/api/planning/stops/:id",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const allowed=["planned_sequence","planned_window_start","planned_window_end","address","customer_name"];
    const keys=Object.keys(req.body).filter(k=>allowed.includes(k));
    if(!keys.length)return res.status(400).json({error:"Keine gültigen Felder"});
    const vals=keys.map(k=>req.body[k]); vals.push(req.params.id);
    const set=keys.map((k,i)=>`${k}=$${i+1}`).join(",");
    const r=(await q(`update trip_stops set ${set} where id=$${vals.length} returning *`,vals))[0];
    if(!r)return res.status(404).json({error:"Stopp nicht gefunden"});
    await audit(req,"PLANNING_STOP_EDIT",`${r.id}: ${keys.join(",")}`);
    res.json(r);
  }catch(e){res.status(500).json({error:e.message});}
});

app.post("/api/planning/trips/:id/assign-driver",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const driver=(await q("select id,name from users where id=$1 and role='Driver'",[req.body.driverId]))[0];
    if(!driver)return res.status(400).json({error:"Fahrer nicht gefunden"});
    const r=(await q("update trips set driver_id=$1 where id=$2 returning *",[driver.id,req.params.id]))[0];
    if(!r)return res.status(404).json({error:"Tour nicht gefunden"});
    await audit(req,"PLANNING_DRIVER_ASSIGN",`${r.trip_number} -> ${driver.name}`);
    res.json(r);
  }catch(e){res.status(500).json({error:e.message});}
});

app.post("/api/planning/trips/:id/reorder",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const ids=Array.isArray(req.body.stopIds)?req.body.stopIds:[];
    for(let i=0;i<ids.length;i++)await q("update trip_stops set planned_sequence=$1,stop_order=$1 where id=$2 and trip_id=$3",[i+1,ids[i],req.params.id]);
    await audit(req,"PLANNING_STOP_REORDER",`${req.params.id}: ${ids.length} Stopps`);
    res.json({ok:true});
  }catch(e){res.status(500).json({error:e.message});}
});

app.get("/api/planning/dispatchers",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const drivers=await q("select id,name,username from users where role='Driver' order by name");
    const vehicles=await q("select id,name,plate from vehicles where active=true order by name");
    res.json({drivers,vehicles});
  }catch(e){res.status(500).json({error:e.message});}
});



// V24: driver working hours, breaks, stop windows and schedule conflict checks
app.get("/api/planning/work-rules",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const drivers=await q(`select u.id,u.name,coalesce(w.work_start,'08:00') work_start,
      coalesce(w.work_end,'17:00') work_end,w.break_start,w.break_end
      from users u left join driver_work_rules w on w.driver_id=u.id
      where u.role='Driver' order by u.name`);
    res.json(drivers);
  }catch(e){res.status(500).json({error:e.message});}
});

app.post("/api/planning/work-rules",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const r=(await q(`insert into driver_work_rules(driver_id,work_start,work_end,break_start,break_end)
      values($1,$2,$3,$4,$5)
      on conflict(driver_id) do update set work_start=excluded.work_start,work_end=excluded.work_end,
      break_start=excluded.break_start,break_end=excluded.break_end returning *`,
      [req.body.driverId,req.body.workStart||'08:00',req.body.workEnd||'17:00',
       req.body.breakStart||null,req.body.breakEnd||null]))[0];
    await audit(req,"WORK_RULE_UPDATED",r.driver_id);res.json(r);
  }catch(e){res.status(500).json({error:e.message});}
});

app.post("/api/planning/check-conflicts",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const trip=(await q(`select t.*,u.name driver_name from trips t left join users u on u.id=t.driver_id where t.id=$1`,[req.body.tripId]))[0];
    if(!trip)return res.status(404).json({error:"Tour nicht gefunden"});
    const rules=trip.driver_id?(await q("select * from driver_work_rules where driver_id=$1",[trip.driver_id]))[0]:null;
    const stops=await q(`select * from trip_stops where trip_id=$1 order by coalesce(planned_sequence,stop_order),id`,[trip.id]);
    const conflicts=[];
    if(!trip.driver_id)conflicts.push("Kein Fahrer zugewiesen");
    if(!trip.vehicle_id && !trip.assigned_vehicle_slot)conflicts.push("Kein Fahrzeug zugewiesen");
    if(Number(trip.weight_kg||0)>1000)conflicts.push("Gewicht über 1.000 KG");
    if(rules && trip.planned_start_at){
      const start=new Date(trip.planned_start_at);
      const [h,m]=String(rules.work_start).split(':').map(Number);
      const [eh,em]=String(rules.work_end).split(':').map(Number);
      const dayStart=new Date(start);dayStart.setHours(h,m,0,0);
      const dayEnd=new Date(start);dayEnd.setHours(eh,em,0,0);
      if(start<dayStart || start>dayEnd)conflicts.push("Tourstart außerhalb der Arbeitszeit");
    }
    for(const st of stops){
      if(st.time_window_start&&st.time_window_end && st.time_window_start>st.time_window_end)
        conflicts.push(`Stopp ${st.stop_order}: Zeitfenster ungültig`);
      if(Number(st.service_minutes||0)>240)conflicts.push(`Stopp ${st.stop_order}: Servicezeit ungewöhnlich hoch`);
    }
    res.json({ok:conflicts.length===0,conflicts,driver:trip.driver_name||null});
  }catch(e){res.status(500).json({error:e.message});}
});

app.post("/api/planning/optimize-stops/:tripId",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const stops=await q(`select * from trip_stops where trip_id=$1 order by id`,[req.params.tripId]);
    const sorted=[...stops].sort((a,b)=>{
      const aw=a.time_window_start||'99:99', bw=b.time_window_start||'99:99';
      if(aw!==bw)return aw.localeCompare(bw);
      return String(a.address||'').localeCompare(String(b.address||''));
    });
    for(let i=0;i<sorted.length;i++)await q("update trip_stops set planned_sequence=$1,stop_order=$1 where id=$2",[i+1,sorted[i].id]);
    await audit(req,"STOP_ORDER_OPTIMIZED",`${req.params.tripId}: ${sorted.length}`);
    res.json({stops:sorted.map((x,i)=>({...x,planned_sequence:i+1}))});
  }catch(e){res.status(500).json({error:e.message});}
});



// V25: route distance/time estimation and route ordering foundation
function v25GeoDistanceKm(a,b){
  if(!a||!b||a.lat==null||a.lng==null||b.lat==null||b.lng==null)return null;
  const R=6371,rad=Math.PI/180, dLat=(b.lat-a.lat)*rad,dLng=(b.lng-a.lng)*rad;
  const x=Math.sin(dLat/2)**2+Math.cos(a.lat*rad)*Math.cos(b.lat*rad)*Math.sin(dLng/2)**2;
  return R*2*Math.atan2(Math.sqrt(x),Math.sqrt(1-x));
}
function v25EstimateMin(km){return km==null?null:Math.max(1,Math.round((km/45)*60));}

app.get("/api/planning/route/:tripId",auth,async(req,res)=>{
  try{
    const trip=(await q("select * from trips where id=$1",[req.params.tripId]))[0];
    if(!trip)return res.status(404).json({error:"Tour nicht gefunden"});
    const stops=await q(`select * from trip_stops where trip_id=$1 order by coalesce(planned_sequence,stop_order),id`,[trip.id]);
    let total=0,minutes=0,prev=null;
    const enriched=stops.map(st=>{
      const cur={lat:st.lat,lng:st.lng};
      const km=v25GeoDistanceKm(prev,cur);
      const min=v25EstimateMin(km);
      if(km!=null)total+=km;
      if(min!=null)minutes+=min;
      prev=cur.lat!=null&&cur.lng!=null?cur:null;
      return {...st,route_distance_from_prev_km:km==null?null:+km.toFixed(2),route_duration_from_prev_min:min};
    });
    const first=enriched[0], last=enriched[enriched.length-1];
    res.json({trip,stops:enriched,total_distance_km:+total.toFixed(2),duration_min:minutes,
      provider:"prototype_haversine_45kmh",note:"Schätzung ohne Live-Verkehr"});
  }catch(e){res.status(500).json({error:e.message});}
});

app.post("/api/planning/route/:tripId/calculate",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const trip=(await q("select * from trips where id=$1",[req.params.tripId]))[0];
    if(!trip)return res.status(404).json({error:"Tour nicht gefunden"});
    const stops=await q(`select * from trip_stops where trip_id=$1 order by coalesce(planned_sequence,stop_order),id`,[trip.id]);
    let total=0,minutes=0,prev=null,seq=1;
    for(const st of stops){
      const cur={lat:st.lat,lng:st.lng};
      const km=v25GeoDistanceKm(prev,cur), min=v25EstimateMin(km);
      if(km!=null)total+=km;if(min!=null)minutes+=min;
      await q(`update trip_stops set planned_sequence=$1,route_distance_from_prev_km=$2,
        route_duration_from_prev_min=$3 where id=$4`,[seq++,km==null?null:+km.toFixed(2),min,st.id]);
      if(cur.lat!=null&&cur.lng!=null)prev=cur;
    }
    await q(`update trips set route_distance_km=$1,route_duration_min=$2,route_provider='prototype_haversine_45kmh' where id=$3`,
      [+total.toFixed(2),minutes,trip.id]);
    await audit(req,"ROUTE_CALCULATED",`${trip.trip_number}: ${total.toFixed(2)} km`);
    res.json({trip_id:trip.id,distance_km:+total.toFixed(2),duration_min:minutes,provider:"prototype_haversine_45kmh"});
  }catch(e){res.status(500).json({error:e.message});}
});

app.post("/api/planning/route/:tripId/optimize",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const stops=await q(`select * from trip_stops where trip_id=$1`,[req.params.tripId]);
    if(!stops.length)return res.json({stops:[]});
    const remaining=[...stops],ordered=[remaining.shift()];
    while(remaining.length){
      const last=ordered[ordered.length-1];
      let best=-1,bestKm=Infinity;
      for(let i=0;i<remaining.length;i++){
        const km=v25GeoDistanceKm(last,remaining[i]);
        if(km!=null&&km<bestKm){bestKm=km;best=i;}
      }
      if(best<0)ordered.push(remaining.shift()); else ordered.push(remaining.splice(best,1)[0]);
    }
    for(let i=0;i<ordered.length;i++)await q("update trip_stops set planned_sequence=$1,stop_order=$1 where id=$2",[i+1,ordered[i].id]);
    await audit(req,"ROUTE_OPTIMIZED",`${req.params.tripId}: ${ordered.length} Stopps`);
    res.json({stops:ordered.map((x,i)=>({...x,planned_sequence:i+1})),method:"nearest_neighbor"});
  }catch(e){res.status(500).json({error:e.message});}
});



// V26: Google Routes API integration with safe prototype fallback
async function v26GoogleRoute(stops){
  if(!GOOGLE_ROUTES_API_KEY || stops.length<2)return null;
  const body={
    origin:{location:{latLng:{latitude:Number(stops[0].lat),longitude:Number(stops[0].lng)}}},
    destination:{location:{latLng:{latitude:Number(stops[stops.length-1].lat),longitude:Number(stops[stops.length-1].lng)}}},
    intermediates:stops.slice(1,-1).map(x=>({location:{latLng:{latitude:Number(x.lat),longitude:Number(x.lng)}}})),
    travelMode:"DRIVE",
    routingPreference:"TRAFFIC_AWARE",
    computeAlternativeRoutes:false,
    routeModifiers:{avoidTolls:false,avoidHighways:false,avoidFerries:false},
    languageCode:"it-IT",
    units:"METRIC"
  };
  const r=await fetch(GOOGLE_ROUTES_URL,{method:"POST",headers:{
    "Content-Type":"application/json","X-Goog-Api-Key":GOOGLE_ROUTES_API_KEY,
    "X-Goog-FieldMask":"routes.distanceMeters,routes.duration,routes.polyline.encodedPolyline,routes.legs.distanceMeters,routes.legs.duration"
  },body:JSON.stringify(body)});
  if(!r.ok)throw new Error("Google Routes API: "+r.status);
  const d=await r.json(), route=d.routes?.[0];
  if(!route)throw new Error("Keine Route von Google erhalten");
  return {
    distance_km:+(Number(route.distanceMeters||0)/1000).toFixed(2),
    duration_min:Math.max(1,Math.round(parseFloat(String(route.duration||"0s"))/60)),
    polyline:route.polyline?.encodedPolyline||null,
    legs:(route.legs||[]).map(x=>({distance_km:+(Number(x.distanceMeters||0)/1000).toFixed(2),duration_min:Math.max(1,Math.round(parseFloat(String(x.duration||"0s"))/60))}))
  };
}

app.post("/api/planning/route/:tripId/google",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    if(!GOOGLE_ROUTES_API_KEY)return res.status(503).json({error:"GOOGLE_ROUTES_API_KEY ist nicht konfiguriert"});
    const trip=(await q("select * from trips where id=$1",[req.params.tripId]))[0];
    if(!trip)return res.status(404).json({error:"Tour nicht gefunden"});
    const stops=await q(`select * from trip_stops where trip_id=$1 and lat is not null and lng is not null
      order by coalesce(planned_sequence,stop_order),id`,[trip.id]);
    if(stops.length<2)return res.status(400).json({error:"Mindestens 2 Stopps mit GPS-Koordinaten erforderlich"});
    const route=await v26GoogleRoute(stops);
    for(let i=0;i<route.legs.length;i++){
      const st=stops[i+1];
      await q(`update trip_stops set route_distance_from_prev_km=$1,route_duration_from_prev_min=$2 where id=$3`,
        [route.legs[i].distance_km,route.legs[i].duration_min,st.id]);
    }
    await q(`update trips set route_distance_km=$1,route_duration_min=$2,route_source='Google Routes API',
      traffic_aware=true,route_updated_at=now() where id=$3`,
      [route.distance_km,route.duration_min,trip.id]);
    await audit(req,"GOOGLE_ROUTE_CALCULATED",`${trip.trip_number}: ${route.distance_km} km / ${route.duration_min} min`);
    res.json({trip_id:trip.id,...route,source:"Google Routes API",traffic_aware:true,updated_at:new Date().toISOString()});
  }catch(e){res.status(500).json({error:e.message});}
});

app.get("/api/planning/route/:tripId/live",auth,async(req,res)=>{
  try{
    const t=(await q("select id,trip_number,route_distance_km,route_duration_min,route_source,traffic_aware,route_updated_at,eta_at,eta_minutes from trips where id=$1",[req.params.tripId]))[0];
    if(!t)return res.status(404).json({error:"Tour nicht gefunden"});
    res.json(t);
  }catch(e){res.status(500).json({error:e.message});}
});



// V27: driver shift planning and utilization
app.get("/api/planning/shifts",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const date=req.query.date||new Date().toISOString().slice(0,10);
    const rows=await q(`select u.id driver_id,u.name,coalesce(s.status,'planned') status,s.start_at,s.end_at,s.break_minutes
      from users u left join driver_shifts s on s.driver_id=u.id and s.shift_date=$1
      where u.role='Driver' order by u.name`,[date]);
    res.json({date,drivers:rows});
  }catch(e){res.status(500).json({error:e.message});}
});

app.post("/api/planning/shifts",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const r=(await q(`insert into driver_shifts(driver_id,shift_date,start_at,end_at,break_minutes,status)
      values($1,$2,$3,$4,$5,'planned')
      on conflict(driver_id,shift_date) do update set start_at=excluded.start_at,end_at=excluded.end_at,
      break_minutes=excluded.break_minutes,status='planned' returning *`,
      [req.body.driverId,req.body.date,req.body.startAt,req.body.endAt,Number(req.body.breakMinutes||0)]))[0];
    await audit(req,"DRIVER_SHIFT_PLANNED",`${r.driver_id} ${r.shift_date}`);res.json(r);
  }catch(e){res.status(500).json({error:e.message});}
});

app.post("/api/planning/validate-day",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const date=req.body.date||new Date().toISOString().slice(0,10);
    const drivers=await q(`select u.id,u.name,s.start_at,s.end_at,s.break_minutes,
      coalesce(sum(t.planned_minutes),0) planned_minutes,count(t.id)::int trip_count
      from users u left join driver_shifts s on s.driver_id=u.id and s.shift_date=$1
      left join trips t on t.driver_id=u.id and t.shift_date=$1
      where u.role='Driver' group by u.id,u.name,s.start_at,s.end_at,s.break_minutes order by u.name`,[date]);
    const result=drivers.map(d=>{
      const warnings=[];
      if(!d.start_at||!d.end_at)warnings.push("Keine Schichtzeit hinterlegt");
      const start=d.start_at?new Date(d.start_at):null,end=d.end_at?new Date(d.end_at):null;
      const available=start&&end?Math.max(0,Math.round((end-start)/60000)-Number(d.break_minutes||0)):0;
      if(available && Number(d.planned_minutes)>available)warnings.push(`Plan überschreitet verfügbare Zeit um ${Number(d.planned_minutes)-available} Min.`);
      return {...d,available_minutes:available,warnings};
    });
    res.json({date,drivers:result,ok:result.every(x=>!x.warnings.length)});
  }catch(e){res.status(500).json({error:e.message});}
});



// V28: automatic two-vehicle dispatch engine
function v28PriorityScore(p){return p==="urgent"?0:p==="high"?1:2;}
app.post("/api/planning/auto-dispatch",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const date=req.body.date||new Date().toISOString().slice(0,10);
    const orders=await q(`select o.*,c.company customer_company from orders o left join customers c on c.id=o.customer_id
      where o.status in ('new','planned') and o.assigned_trip_id is null
      and (o.requested_date is null or o.requested_date=$1)
      order by case o.priority when 'urgent' then 0 when 'high' then 1 else 2 end,
      coalesce(o.time_window_start,'23:59') asc,o.delivery_city,o.id`,[date]);
    const drivers=await q(`select u.id,u.name,s.start_at,s.end_at,s.break_minutes
      from users u left join driver_shifts s on s.driver_id=u.id and s.shift_date=$1
      where u.role='Driver' order by u.name`,[date]);
    const vehicles=await q("select * from vehicles where active=true order by name limit 2");
    if(!vehicles.length)return res.status(400).json({error:"Keine aktiven Fahrzeuge"});
    const buckets=vehicles.map((v,i)=>({slot:i+1,vehicle:v,driver:drivers[i]||null,orders:[],weight:0,minutes:0}));
    const rejected=[];
    for(const o of orders){
      const w=Number(o.weight_kg||0), service=Number(o.estimated_service_min||15);
      let candidates=buckets.filter(b=>b.weight+w<=1000);
      candidates=candidates.filter(b=>{
        if(!b.driver||!b.driver.start_at||!b.driver.end_at)return true;
        const avail=Math.max(0,Math.round((new Date(b.driver.end_at)-new Date(b.driver.start_at))/60000)-Number(b.driver.break_minutes||0));
        return b.minutes+service<=avail;
      });
      candidates.sort((a,b)=> (a.weight-b.weight)|| (a.minutes-b.minutes));
      const pick=candidates[0];
      if(!pick){rejected.push({order_id:o.id,reason:"Kapazität oder Fahrerzeit überschritten"});continue;}
      pick.orders.push(o);pick.weight+=w;pick.minutes+=service+20; // route-time reserve
    }
    const created=[];
    for(const b of buckets){
      if(!b.orders.length)continue;
      const revenue=b.orders.reduce((a,o)=>a+Number(o.price_net||0),0);
      const trip=(await q(`insert into trips(trip_number,weight_kg,pieces,status,driver_id,vehicle_id,assigned_vehicle_slot,
        planning_date,shift_date,planned_sequence,price_net,planned_revenue_net,planned_minutes,auto_planned,priority,notes)
        values($1,$2,$3,'Planned',$4,$5,$6,$7,$7,1,$8,$8,$9,true,$10,'V28 automatische Disposition') returning *`,
        ["AUTO-"+Date.now().toString().slice(-7)+"-"+b.slot,b.weight,b.orders.reduce((a,o)=>a+Number(o.pieces||0),0),
         b.driver?.id||null,b.vehicle.id,b.slot,date,revenue,b.minutes,
         b.orders.some(o=>o.priority==="urgent")?"urgent":b.orders.some(o=>o.priority==="high")?"high":"normal"]))[0];
      let seq=1;
      for(const o of b.orders){
        await q("update orders set assigned_trip_id=$1,status='planned' where id=$2",[trip.id,o.id]);
        await q(`insert into trip_stops(trip_id,stop_order,planned_sequence,address,customer_name,time_window_start,time_window_end,service_minutes)
          values($1,$2,$2,$3,$4,$5,$6,$7)`,
          [trip.id,seq++,o.delivery_address,o.customer_company,o.time_window_start,o.time_window_end,o.estimated_service_min||15]);
      }
      created.push({trip,vehicle:b.vehicle,driver:b.driver,orders:b.orders.length});
    }
    await audit(req,"AUTO_DISPATCH",`${date}: ${created.length} Touren, ${rejected.length} abgelehnt`);
    res.json({date,created,rejected,algorithm:"capacity + driver-time + priority heuristic"});
  }catch(e){res.status(500).json({error:e.message});}
});



// V29: route-aware refinement for the two daily tours
function v29Score(order, latePenalty=0){
  const p=order.priority==="urgent"?1000:order.priority==="high"?300:0;
  return p-latePenalty;
}
app.post("/api/planning/optimize-day",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const date=req.body.date||new Date().toISOString().slice(0,10);
    const trips=await q(`select * from trips where planning_date=$1 and status='Planned' order by assigned_vehicle_slot`,[date]);
    const results=[];
    for(const trip of trips){
      const stops=await q(`select s.*,o.priority,o.time_window_start as order_window_start,o.time_window_end as order_window_end
        from trip_stops s left join orders o on o.assigned_trip_id=s.trip_id and o.delivery_address=s.address
        where s.trip_id=$1 order by coalesce(s.planned_sequence,s.stop_order),s.id`,[trip.id]);
      if(!stops.length)continue;
      // Keep urgent/time-window stops first, then use nearest-neighbor when GPS exists.
      const remaining=[...stops], ordered=[];
      remaining.sort((a,b)=>{
        const ap=a.order_window_start||a.time_window_start||'99:99';
        const bp=b.order_window_start||b.time_window_start||'99:99';
        const ps=(v)=>v==="urgent"?0:v==="high"?1:2;
        return (ps(a.priority)-ps(b.priority)) || ap.localeCompare(bp);
      });
      const seeded=remaining.shift(); ordered.push(seeded);
      while(remaining.length){
        const last=ordered[ordered.length-1];
        let best=0,bestScore=Infinity;
        for(let i=0;i<remaining.length;i++){
          const r=remaining[i];
          const km=v25GeoDistanceKm(last,r);
          const distance=km==null?0:km;
          const window=r.order_window_start||r.time_window_start||'99:99';
          const priorityPenalty=r.priority==="urgent"?-100:r.priority==="high"?-20:0;
          const score=distance+priorityPenalty+(window==="99:99"?0:i*0.01);
          if(score<bestScore){bestScore=score;best=i;}
        }
        ordered.push(remaining.splice(best,1)[0]);
      }
      let totalKm=0,totalMin=0,prev=null;
      for(let i=0;i<ordered.length;i++){
        const st=ordered[i], km=v25GeoDistanceKm(prev,st);
        const min=v25EstimateMin(km);
        if(km!=null)totalKm+=km;if(min!=null)totalMin+=min;
        await q(`update trip_stops set planned_sequence=$1,stop_order=$1,
          route_distance_from_prev_km=$2,route_duration_from_prev_min=$3 where id=$4`,
          [i+1,km==null?null:+km.toFixed(2),min,st.id]);
        if(st.lat!=null&&st.lng!=null)prev=st;
      }
      const score=+(10000-(totalKm*10)-(totalMin*2)+ordered.reduce((a,x)=>a+(x.priority==="urgent"?1000:x.priority==="high"?300:0),0)).toFixed(2);
      await q(`update trips set route_distance_km=$1,route_duration_min=$2,optimization_score=$3,
        optimization_source='V29 heuristic',optimized_at=now() where id=$4`,
        [+totalKm.toFixed(2),totalMin,score,trip.id]);
      results.push({trip_id:trip.id,trip_number:trip.trip_number,distance_km:+totalKm.toFixed(2),duration_min:totalMin,score,stop_count:ordered.length});
    }
    await audit(req,"DAY_OPTIMIZED",`${date}: ${results.length} Touren`);
    res.json({date,results,method:"priority + time-window + nearest-neighbor heuristic"});
  }catch(e){res.status(500).json({error:e.message});}
});

app.get("/api/planning/optimization/:date",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const rows=await q(`select t.id,t.trip_number,t.assigned_vehicle_slot,t.route_distance_km,t.route_duration_min,
      t.optimization_score,t.optimization_source,t.optimized_at,t.priority,u.name driver_name,v.name vehicle_name
      from trips t left join users u on u.id=t.driver_id left join vehicles v on v.id=t.vehicle_id
      where t.planning_date=$1 order by t.assigned_vehicle_slot`,[req.params.date]);
    res.json(rows);
  }catch(e){res.status(500).json({error:e.message});}
});



// V30: live control center feed
app.get("/api/control-center/live",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const rows=await q(`select t.id,t.trip_number,t.status,t.live_status,t.current_lat,t.current_lng,
      t.last_driver_ping_at,t.eta_at,t.eta_minutes,t.route_distance_km,t.route_duration_min,
      t.assigned_vehicle_slot,t.priority,u.name driver_name,v.name vehicle_name,v.plate,
      c.company customer_company
      from trips t left join users u on u.id=t.driver_id left join vehicles v on v.id=t.vehicle_id
      left join customers c on c.id=t.customer_id
      where t.status not in ('Delivered','Cancelled')
      order by coalesce(t.assigned_vehicle_slot,99),t.trip_number`);
    const stopRows=await q(`select s.id,s.trip_id,s.stop_order,s.planned_sequence,s.address,s.customer_name,s.status,
      s.lat,s.lng,s.eta_at,s.geofence_arrived_at,s.delivered_at
      from trip_stops s join trips t on t.id=s.trip_id
      where t.status not in ('Delivered','Cancelled')
      order by s.trip_id,coalesce(s.planned_sequence,s.stop_order),s.id`);
    const byTrip={};for(const st of stopRows)(byTrip[st.trip_id]??=[]).push(st);
    const now=Date.now();
    res.json({server_time:new Date().toISOString(),vehicles:rows.map(x=>({
      ...x,stale_seconds:x.last_driver_ping_at?Math.max(0,Math.round((now-new Date(x.last_driver_ping_at).getTime())/1000)):null,
      stops:byTrip[x.id]||[]
    }))});
  }catch(e){res.status(500).json({error:e.message});}
});

app.post("/api/control-center/ping",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const r=(await q(`update trips set live_status='online',last_driver_ping_at=now()
      where id=$1 returning id,trip_number,last_driver_ping_at`,[req.body.tripId]))[0];
    if(!r)return res.status(404).json({error:"Tour nicht gefunden"});
    res.json(r);
  }catch(e){res.status(500).json({error:e.message});}
});



// V31: Google Maps browser configuration and map-ready live feed
app.get("/api/config/maps",auth,async(req,res)=>{
  res.json({googleMapsBrowserKey:process.env.GOOGLE_MAPS_BROWSER_KEY||""});
});



// V32: map route feed and stop coordinates
app.get("/api/control-center/map-data",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const trips=await q(`select t.id,t.trip_number,t.assigned_vehicle_slot,t.status,t.priority,t.current_lat,t.current_lng,
      t.route_polyline,t.map_color,t.eta_minutes,u.name driver_name,v.name vehicle_name
      from trips t left join users u on u.id=t.driver_id left join vehicles v on v.id=t.vehicle_id
      where t.status not in ('Delivered','Cancelled')
      order by coalesce(t.assigned_vehicle_slot,99),t.trip_number`);
    const stops=await q(`select s.id,s.trip_id,s.stop_order,s.planned_sequence,s.address,s.customer_name,s.status,
      s.lat,s.lng,s.eta_at,s.geofence_arrived_at,s.delivered_at
      from trip_stops s join trips t on t.id=s.trip_id
      where t.status not in ('Delivered','Cancelled') and s.lat is not null and s.lng is not null
      order by s.trip_id,coalesce(s.planned_sequence,s.stop_order),s.id`);
    res.json({trips,stops});
  }catch(e){res.status(500).json({error:e.message});}
});

app.post("/api/control-center/map-color/:tripId",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const color=String(req.body.color||"").slice(0,32);
    const r=(await q("update trips set map_color=$1 where id=$2 returning id,map_color",[color,req.params.tripId]))[0];
    if(!r)return res.status(404).json({error:"Tour nicht gefunden"});
    res.json(r);
  }catch(e){res.status(500).json({error:e.message});}
});



// V33: live control alerts and vehicle detail
app.get("/api/control-center/alerts",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const rows=await q(`select a.*,t.trip_number,u.name driver_name,v.name vehicle_name
      from control_alerts a left join trips t on t.id=a.trip_id left join users u on u.id=t.driver_id
      left join vehicles v on v.id=t.vehicle_id
      where a.acknowledged=false order by case a.severity when 'critical' then 0 when 'warning' then 1 else 2 end,a.created_at desc`);
    res.json(rows);
  }catch(e){res.status(500).json({error:e.message});}
});

app.post("/api/control-center/alerts/:id/ack",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const r=(await q("update control_alerts set acknowledged=true,acknowledged_at=now() where id=$1 returning *",[req.params.id]))[0];
    if(!r)return res.status(404).json({error:"Alarm nicht gefunden"});
    await audit(req,"CONTROL_ALERT_ACK",r.id);res.json(r);
  }catch(e){res.status(500).json({error:e.message});}
});

app.post("/api/control-center/alerts/check",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const trips=await q(`select id,trip_number,driver_id,last_driver_ping_at,eta_at,eta_minutes,status
      from trips where status not in ('Delivered','Cancelled')`);
    const created=[];
    for(const t of trips){
      if(t.last_driver_ping_at){
        const age=(Date.now()-new Date(t.last_driver_ping_at).getTime())/60000;
        if(age>5){
          const exists=(await q(`select id from control_alerts where trip_id=$1 and type='GPS_STALE' and acknowledged=false
            and created_at>now()-interval '30 minutes'`,[t.id]))[0];
          if(!exists){
            const a=(await q(`insert into control_alerts(trip_id,type,severity,message) values($1,'GPS_STALE','warning',$2) returning *`,
              [t.id,`GPS seit ${Math.round(age)} Minuten nicht aktualisiert`]))[0];created.push(a);
          }
        }
      }else{
        const exists=(await q(`select id from control_alerts where trip_id=$1 and type='NO_GPS' and acknowledged=false`,[t.id]))[0];
        if(!exists){
          const a=(await q(`insert into control_alerts(trip_id,type,severity,message) values($1,'NO_GPS','warning','Keine GPS-Position vorhanden') returning *`,[t.id]))[0];created.push(a);
        }
      }
      if(t.eta_at && new Date(t.eta_at)<new Date() && !['Delivered','Cancelled'].includes(t.status)){
        const exists=(await q(`select id from control_alerts where trip_id=$1 and type='ETA_LATE' and acknowledged=false
          and created_at>now()-interval '30 minutes'`,[t.id]))[0];
        if(!exists){
          const a=(await q(`insert into control_alerts(trip_id,type,severity,message) values($1,'ETA_LATE','critical','ETA überschritten') returning *`,[t.id]))[0];created.push(a);
        }
      }
    }
    res.json({created});
  }catch(e){res.status(500).json({error:e.message});}
});



// V34: realtime driver/dispatch synchronization feed
app.get("/api/sync/state",auth,async(req,res)=>{
  try{
    const since=Number(req.query.since||0);
    const trips=await q(`select t.id,t.trip_number,t.status,t.current_lat,t.current_lng,t.eta_at,t.eta_minutes,
      t.sync_version,t.driver_last_action_at,t.last_driver_ping_at,t.assigned_vehicle_slot,t.driver_id,t.vehicle_id
      from trips t where t.updated_at>now()-interval '24 hours' and t.sync_version>$1 order by t.sync_version`,[since]);
    const stops=await q(`select s.id,s.trip_id,s.status,s.planned_sequence,s.eta_at,s.geofence_arrived_at,s.delivered_at,s.sync_version
      from trip_stops s where s.sync_version>$1 order by s.sync_version`,[since]);
    const users=await q(`select id,name,last_seen_at from users where role='Driver'`);
    const max=Math.max(since,...trips.map(x=>Number(x.sync_version||0)),...stops.map(x=>Number(x.sync_version||0)));
    res.json({server_time:new Date().toISOString(),version:max,trips,stops,drivers:users});
  }catch(e){res.status(500).json({error:e.message});}
});

app.post("/api/driver/heartbeat",auth,roles("Driver"),async(req,res)=>{
  try{
    await q("update users set last_seen_at=now() where id=$1",[req.user.id]);
    if(req.body.tripId)await q(`update trips set last_driver_ping_at=now(),driver_last_action_at=now(),live_status='online',sync_version=sync_version+1 where id=$1 and driver_id=$2`,
      [req.body.tripId,req.user.id]);
    res.json({ok:true,at:new Date().toISOString()});
  }catch(e){res.status(500).json({error:e.message});}
});

app.get("/api/driver/sync",auth,roles("Driver"),async(req,res)=>{
  try{
    const trips=await q(`select t.*,c.company customer_company from trips t left join customers c on c.id=t.customer_id
      where t.driver_id=$1 and t.status not in ('Delivered','Cancelled') order by t.planning_date,t.planned_sequence,t.created_at`,[req.user.id]);
    const stops=await q(`select s.* from trip_stops s join trips t on t.id=s.trip_id where t.driver_id=$1
      and t.status not in ('Delivered','Cancelled') order by t.id,coalesce(s.planned_sequence,s.stop_order),s.id`,[req.user.id]);
    res.json({server_time:new Date().toISOString(),trips,stops});
  }catch(e){res.status(500).json({error:e.message});}
});



// V35: end-to-end driver delivery workflow
app.post("/api/driver/trips/:id/start",auth,roles("Driver"),async(req,res)=>{
  try{
    const t=(await q("select * from trips where id=$1 and driver_id=$2",[req.params.id,req.user.id]))[0];
    if(!t)return res.status(404).json({error:"Tour nicht gefunden"});
    const r=await q(`update trips set status='In Transit',actual_started_at=coalesce(actual_started_at,now()),
      last_driver_ping_at=now(),driver_last_action_at=now(),live_status='online',
      sync_version=sync_version+1,updated_at=now() where id=$1 returning *`,[t.id]);
    await q("update users set last_seen_at=now() where id=$1",[req.user.id]);
    await audit(req,"DRIVER_TRIP_STARTED",r[0].trip_number);
    res.json(r[0]);
  }catch(e){res.status(500).json({error:e.message});}
});

app.post("/api/driver/stops/:id/arrive",auth,roles("Driver"),async(req,res)=>{
  try{
    const s0=(await q(`select s.*,t.trip_number,t.driver_id from trip_stops s join trips t on t.id=s.trip_id
      where s.id=$1 and t.driver_id=$2`,[req.params.id,req.user.id]))[0];
    if(!s0)return res.status(404).json({error:"Stopp nicht gefunden"});
    const r=await q(`update trip_stops set geofence_arrived_at=coalesce(geofence_arrived_at,now()),
      sync_version=sync_version+1,delivered_at=null where id=$1 returning *`,[s0.id]);
    await q("update users set last_seen_at=now() where id=$1",[req.user.id]);
    await q("update trips set last_driver_ping_at=now(),driver_last_action_at=now(),sync_version=sync_version+1,updated_at=now() where id=$1",[s0.trip_id]);
    await audit(req,"DRIVER_STOP_ARRIVED",s0.trip_number+" / "+s0.id);
    res.json(r[0]);
  }catch(e){res.status(500).json({error:e.message});}
});

app.post("/api/driver/stops/:id/deliver",auth,roles("Driver"),async(req,res)=>{
  try{
    const s0=(await q(`select s.*,t.trip_number,t.driver_id,t.id trip_id from trip_stops s join trips t on t.id=s.trip_id
      where s.id=$1 and t.driver_id=$2`,[req.params.id,req.user.id]))[0];
    if(!s0)return res.status(404).json({error:"Stopp nicht gefunden"});
    const kg=Math.max(0,Number(req.body.delivered_kg||0)), pieces=Math.max(0,parseInt(req.body.delivered_pieces||s0.pieces||1,10));
    const note=String(req.body.delivery_note||"").slice(0,2000);
    const photo=String(req.body.photo_data||"");
    const sig=String(req.body.signature_data||"");
    if(kg>1000)return res.status(400).json({error:"Maximal 1000 KG"});
    if(photo.length>2_000_000||sig.length>500_000)return res.status(413).json({error:"Proof-Datei zu groß"});
    const r=await q(`update trip_stops set delivered_at=now(),delivered_kg=$2,delivered_pieces=$3,
      delivery_note=$4,delivery_photo=$5,signature_data=$6,sync_version=sync_version+1 where id=$1 returning *`,
      [s0.id,kg,pieces,note,photo||null,sig||null]);
    await q("update trips set last_driver_ping_at=now(),driver_last_action_at=now(),sync_version=sync_version+1,updated_at=now() where id=$1",[s0.trip_id]);
    const open=await q("select count(*)::int n from trip_stops where trip_id=$1 and delivered_at is null",[s0.trip_id]);
    if(open[0].n===0){
      await q(`update trips set status='Delivered',live_status='offline',actual_finished_at=coalesce(actual_finished_at,now()),
        sync_version=sync_version+1,updated_at=now() where id=$1`,[s0.trip_id]);
      const trip=(await q("select * from trips where id=$1",[s0.trip_id]))[0];
      if(trip.price_net>0){try{await createInvoice38(req,trip.id)}catch(e){await autoInvoice(req,trip);}}
      await audit(req,"TRIP_DELIVERED",trip.trip_number);
      try{await createDdt37(req,trip.id);}catch(ddtErr){console.error('DDT auto-create failed',ddtErr.message);}
    }
    await audit(req,"DRIVER_STOP_DELIVERED",s0.trip_number+" / "+s0.id);
    res.json({stop:r[0],trip_completed:open[0].n===0});
  }catch(e){res.status(500).json({error:e.message});}
});



// V37: automatic DDT

function escHtml37(v){return String(v??"").replace(/[&<>"']/g,m=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[m]));}
async function createDdt37(req,tripId){
  const exists=(await q("select * from delivery_documents where trip_id=$1",[tripId]))[0];
  if(exists)return exists;
  const t=(await q(`select t.*,c.company customer_company,c.address customer_address,c.city customer_city,c.vat_id
    from trips t left join customers c on c.id=t.customer_id where t.id=$1`,[tripId]))[0];
  if(!t)throw new Error("Tour nicht gefunden");
  const stops=await q(`select * from trip_stops where trip_id=$1 order by coalesce(planned_sequence,stop_order),id`,[tripId]);
  const n=await q(`select 'DDT-'||extract(year from current_date)::int||'-'||lpad((coalesce(max(cast(split_part(document_number,'-',3) as int)),0)+1)::text,5,'0') n
    from delivery_documents where document_number like 'DDT-'||extract(year from current_date)::int||'-%'`);
  const num=n[0].n;
  const rows=stops.map((x,i)=>`<tr><td>${i+1}</td><td>${escHtml37(x.address)}</td><td>${escHtml37(x.customer_name||"")}</td><td>${escHtml37(x.delivered_kg||0)} KG</td><td>${escHtml37(x.delivered_pieces||x.pieces||1)}</td><td>${x.delivered_at?v189DateOnly(x.delivered_at):""}</td></tr>`).join("");
  const proof=stops.map((x,i)=>`<div class="proof"><b>Stopp ${i+1}</b> · ${escHtml37(x.address)}<br>
    Zustellung: ${x.delivered_at?v189DateOnly(x.delivered_at):"-"} · GPS: ${x.proof_lat??"-"}, ${x.proof_lng??"-"}<br>
    Genauigkeit: ${x.proof_accuracy?Math.round(x.proof_accuracy)+" m":"-"} · Notiz: ${escHtml37(x.delivery_note||"")}
    ${x.signature_data?`<br><img class="sig" src="${x.signature_data}" alt="Unterschrift">`:""}
    ${x.delivery_photo?`<br><img class="photo" src="${x.delivery_photo}" alt="Lieferfoto">`:""}
  </div>`).join("");
  const doc=`<!doctype html><html><head><meta charset="utf-8"><title>${num}</title><style>
    body{font-family:Arial,sans-serif;margin:32px;color:#1f2937}h1{margin:0 0 4px}h2{margin-top:28px}
    table{width:100%;border-collapse:collapse;margin-top:18px}th,td{border:1px solid #d1d5db;padding:7px;text-align:left;font-size:12px}
    .meta{margin:16px 0;padding:12px;background:#f5f7fa}.proof{border:1px solid #ddd;padding:10px;margin:10px 0;page-break-inside:avoid}
    .sig{max-width:260px;max-height:100px;border:1px solid #ddd}.photo{max-width:360px;max-height:240px;display:block;margin-top:8px}
    .footer{margin-top:30px;font-size:11px;color:#667085}@media print{button{display:none}}
  </style></head><body>
  <h1>LIEFERSCHEIN</h1><div>${num}</div>
  <div class="meta"><b>Tour:</b> ${escHtml37(t.trip_number)}<br><b>Kunde:</b> ${escHtml37(t.customer_company||"")}<br>
  <b>Adresse:</b> ${escHtml37(t.customer_address||"")}, ${escHtml37(t.customer_city||"")}<br>
  <b>USt-ID:</b> ${escHtml37(t.vat_id||"-")}<br><b>Ausgestellt:</b> ${new Date().toLocaleString("it-IT")}</div>
  <table><thead><tr><th>#</th><th>Adresse</th><th>Empfänger</th><th>KG</th><th>Stück</th><th>Zeit</th></tr></thead><tbody>${rows}</tbody></table>
  <h2>Zustellnachweise</h2>${proof}
  <div class="footer">Digital erzeugter Zustellbeleg. Für steuerliche/gesetzliche Anforderungen an italienische DDT/FatturaPA bitte die finale Vorlage fachlich prüfen.</div>
  <script>window.onload=()=>setTimeout(()=>window.print(),350)</script></body></html>`;
  const r=await q(`insert into delivery_documents(trip_id,document_number,issued_at,status,proof_complete,pdf_html)
    values($1,$2,now(),'Completed',$3,$4) returning *`,[tripId,num,stops.every(x=>x.delivered_at),doc]);
  return r[0];
}
app.post("/api/trips/:id/ddt",auth,roles("Admin","Dispatcher","Accounting"),async(req,res)=>{
  try{const d=await createDdt37(req,req.params.id);await audit(req,"DDT_CREATED",d.document_number);res.json(d)}
  catch(e){res.status(500).json({error:e.message})}
});
app.get("/api/trips/:id/ddt",auth,async(req,res)=>{
  try{
    const d=(await q("select * from delivery_documents where trip_id=$1",[req.params.id]))[0];
    if(!d)return res.status(404).json({error:"DDT nicht vorhanden"});
    if(req.user.role==="Driver"){
      const own=(await q("select 1 from trips where id=$1 and driver_id=$2",[req.params.id,req.user.id]))[0];
      if(!own)return res.status(403).json({error:"Not permitted"});
    }
    res.json(d);
  }catch(e){res.status(500).json({error:e.message})}
});

// V36: digital proof package (GPS + timestamp + signature + photo)
app.post("/api/driver/stops/:id/proof",auth,roles("Driver"),async(req,res)=>{
  try{
    const st=(await q(`select s.*,t.trip_number,t.driver_id,t.id trip_id from trip_stops s join trips t on t.id=s.trip_id
      where s.id=$1 and t.driver_id=$2`,[req.params.id,req.user.id]))[0];
    if(!st)return res.status(404).json({error:"Stopp nicht gefunden"});
    const lat=req.body.lat==null?null:Number(req.body.lat), lng=req.body.lng==null?null:Number(req.body.lng);
    const acc=req.body.accuracy==null?null:Number(req.body.accuracy);
    if(lat!=null && (!Number.isFinite(lat)||lat<-90||lat>90))return res.status(400).json({error:"Ungültige Latitude"});
    if(lng!=null && (!Number.isFinite(lng)||lng<-180||lng>180))return res.status(400).json({error:"Ungültige Longitude"});
    const photo=String(req.body.photo_data||"");
    const sig=String(req.body.signature_data||"");
    if(photo.length>3_000_000||sig.length>700_000)return res.status(413).json({error:"Nachweis zu groß"});
    const r=await q(`update trip_stops set delivery_photo=coalesce(nullif($2,''),delivery_photo),
      signature_data=coalesce(nullif($3,''),signature_data),proof_lat=$4,proof_lng=$5,proof_accuracy=$6,
      proof_at=now(),proof_device=$7,sync_version=sync_version+1 where id=$1 returning *`,
      [st.id,photo,sig,lat,lng,acc,String(req.body.device||"mobile").slice(0,100)]);
    await q("update trips set current_lat=coalesce($2,current_lat),current_lng=coalesce($3,current_lng),last_driver_ping_at=now(),driver_last_action_at=now(),sync_version=sync_version+1,updated_at=now() where id=$1",[st.trip_id,lat,lng]);
    await audit(req,"DELIVERY_PROOF_CAPTURED",st.trip_number+" / "+st.id);
    res.json({ok:true,stop:r[0],captured_at:r[0].proof_at});
  }catch(e){res.status(500).json({error:e.message});}
});

app.get("/api/driver/stops/:id/proof",auth,async(req,res)=>{
  try{
    const st=(await q(`select s.id,s.trip_id,s.delivery_photo,s.signature_data,s.proof_lat,s.proof_lng,s.proof_accuracy,s.proof_at,s.proof_device
      from trip_stops s join trips t on t.id=s.trip_id where s.id=$1 and (t.driver_id=$2 or $3 in ('Admin','Dispatcher','Accounting'))`,
      [req.params.id,req.user.id,req.user.role]))[0];
    if(!st)return res.status(404).json({error:"Nachweis nicht gefunden"});
    res.json(st);
  }catch(e){res.status(500).json({error:e.message});}
});


// V38: invoice automation

function escHtml38(v){return String(v??"").replace(/[&<>"']/g,m=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[m]));}
async function createInvoice38(req,tripId){
  const ex=(await q("select * from invoices where trip_id=$1",[tripId]))[0]; if(ex)return ex;
  const t=(await q(`select t.*,c.company customer_company,c.address customer_address,c.city customer_city,c.vat_id,c.email customer_email
    from trips t left join customers c on c.id=t.customer_id where t.id=$1`,[tripId]))[0];
  if(!t)throw new Error("Tour nicht gefunden");
  const net=Number(t.price_net||0); if(net<=0)throw new Error("Tour hat keinen Rechnungspreis");
  const vat=Number((net*0.22).toFixed(2)), gross=Number((net+vat).toFixed(2)), terms=30;
  const n=await q(`select 'INV-'||extract(year from current_date)::int||'-'||lpad((coalesce(max(cast(split_part(invoice_number,'-',3) as int)),0)+1)::text,4,'0') n
    from invoices where invoice_number like 'INV-'||extract(year from current_date)::int||'-%'`);
  const num=n[0].n;
  const doc=`<!doctype html><html><head><meta charset="utf-8"><title>${num}</title><style>
    body{font-family:Arial,sans-serif;margin:38px;color:#1f2937}h1{margin-bottom:4px}.box{padding:14px;background:#f5f7fa;margin:18px 0}
    table{width:100%;border-collapse:collapse;margin-top:24px}td,th{padding:9px;border-bottom:1px solid #ddd;text-align:left}.right{text-align:right}
    .total{font-size:18px;font-weight:700}.footer{margin-top:45px;font-size:11px;color:#667085}@media print{button{display:none}}
  </style></head><body><h1>RECHNUNG</h1><div>${num}</div>
  <div class="box"><b>Kunde</b><br>${escHtml38(t.customer_company||"")}<br>${escHtml38(t.customer_address||"")}<br>${escHtml38(t.customer_city||"")}<br>USt-ID: ${escHtml38(t.vat_id||"-")}</div>
  <div><b>Rechnungsdatum:</b> ${new Date().toLocaleDateString("it-IT")}<br><b>Zahlungsziel:</b> ${new Date(Date.now()+terms*86400000).toLocaleDateString("it-IT")} (${terms} Tage)<br><b>Tour:</b> ${escHtml38(t.trip_number)}</div>
  <table><tr><th>Leistung</th><th class="right">Netto</th></tr><tr><td>Transportleistung ${escHtml38(t.trip_number)}</td><td class="right">${net.toFixed(2)} EUR</td></tr>
  <tr><td>IVA 22%</td><td class="right">${vat.toFixed(2)} EUR</td></tr><tr class="total"><td>Gesamt</td><td class="right">${gross.toFixed(2)} EUR</td></tr></table>
  <div class="footer">Technisch erzeugte Rechnungsvorlage. Die steuerliche und elektronische Rechnungscompliance für Italien ist separat fachlich zu prüfen.</div>
  <script>window.onload=()=>setTimeout(()=>window.print(),350)</script></body></html>`;
  const due=new Date(Date.now()+terms*86400000).toISOString().slice(0,10);
  const r=await q(`insert into invoices(invoice_number,customer_id,trip_id,issue_date,due_date,net,vat_rate,vat,gross,status,description,currency,payment_terms_days,pdf_html)
    values($1,$2,$3,current_date,$4,$5,22,$6,$7,'Open',$8,'EUR',$9,$10) returning *`,
    [num,t.customer_id,t.id,due,net,vat,gross,"Transportleistung "+t.trip_number,terms,doc]);
  return r[0];
}
app.post("/api/invoices/from-trip/:id",auth,roles("Admin","Dispatcher","Accounting"),async(req,res)=>{
  try{const inv=await createInvoice38(req,req.params.id);await audit(req,"INVOICE_CREATED",inv.invoice_number);res.json(inv)}
  catch(e){res.status(400).json({error:e.message})}
});
app.get("/api/invoices/overview",auth,roles("Admin","Dispatcher","Accounting"),async(req,res)=>{
  try{
    const rows=await q(`select i.*,c.company customer_company,t.trip_number,
      case when i.status='Paid' then 'Paid' when i.due_date<current_date then 'Overdue' else 'Open' end derived_status
      from invoices i left join customers c on c.id=i.customer_id left join trips t on t.id=i.trip_id order by i.issue_date desc,i.invoice_number desc`);
    const total=rows.reduce((a,x)=>a+Number(x.gross||0),0),open=rows.filter(x=>x.derived_status==='Open').reduce((a,x)=>a+Number(x.gross||0),0),overdue=rows.filter(x=>x.derived_status==='Overdue').reduce((a,x)=>a+Number(x.gross||0),0);
    res.json({rows,total,open,overdue});
  }catch(e){res.status(500).json({error:e.message})}
});
app.post("/api/invoices/:id/pay",auth,roles("Admin","Accounting"),async(req,res)=>{
  try{const r=await q("update invoices set status='Paid',paid_at=now() where id=$1 returning *",[req.params.id]);if(!r[0])return res.status(404).json({error:"Rechnung nicht gefunden"});await audit(req,"INVOICE_PAID",r[0].invoice_number);res.json(r[0])}
  catch(e){res.status(500).json({error:e.message})}
});
app.get("/api/invoices/:id",auth,roles("Admin","Dispatcher","Accounting"),async(req,res)=>{
  try{const r=await q("select * from invoices where id=$1",[req.params.id]);if(!r[0])return res.status(404).json({error:"Rechnung nicht gefunden"});res.json(r[0])}
  catch(e){res.status(500).json({error:e.message})}
});


// V39: customer portal

function hash39(v){return require("crypto").createHash("sha256").update(String(v)).digest("hex");}
async function portalAuth39(req,res,next){
  try{
    const raw=String(req.headers["x-portal-token"]||req.query.token||"");
    if(!raw)return res.status(401).json({error:"Portal token required"});
    const r=await q(`select * from customer_portal_tokens where token_hash=$1 and expires_at>now()`,[hash39(raw)]);
    if(!r[0])return res.status(401).json({error:"Portal token invalid or expired"});
    req.portal=r[0]; await q("update customer_portal_tokens set last_used_at=now() where id=$1",[r[0].id]); next();
  }catch(e){res.status(401).json({error:"Portal authentication failed"})}
}
app.post("/api/customers/:id/portal-token",auth,roles("Admin","Dispatcher","Accounting"),async(req,res)=>{
  try{
    const c=(await q("select id,email,company from customers where id=$1",[req.params.id]))[0];
    if(!c)return res.status(404).json({error:"Kunde nicht gefunden"});
    const raw=require("crypto").randomBytes(32).toString("hex"), exp=new Date(Date.now()+30*86400000);
    await q("insert into customer_portal_tokens(customer_id,token_hash,expires_at) values($1,$2,$3)",[c.id,hash39(raw),exp]);
    await audit(req,"CUSTOMER_PORTAL_TOKEN_CREATED",c.company);
    res.json({token:raw,expires_at:exp,portal_url:"/portal.html?token="+raw});
  }catch(e){res.status(500).json({error:e.message})}
});
app.get("/api/portal/summary",portalAuth39,async(req,res)=>{
  try{
    const inv=await q(`select i.id,i.invoice_number,i.issue_date,i.due_date,i.net,i.vat,i.gross,i.status,
      case when i.status='Paid' then 'Paid' when i.due_date<current_date then 'Overdue' else 'Open' end derived_status
      from invoices i where i.customer_id=$1 order by i.issue_date desc`,[req.portal.customer_id]);
    const dd=await q(`select d.id,d.document_number,d.issued_at,d.status,d.trip_id
      from delivery_documents d join trips t on t.id=d.trip_id where t.customer_id=$1 order by d.issued_at desc`,[req.portal.customer_id]);
    res.json({customer_id:req.portal.customer_id,invoices:inv,documents:dd});
  }catch(e){res.status(500).json({error:e.message})}
});
app.get("/api/portal/invoices/:id",portalAuth39,async(req,res)=>{
  const r=await q("select * from invoices where id=$1 and customer_id=$2",[req.params.id,req.portal.customer_id]);
  if(!r[0])return res.status(404).json({error:"Rechnung nicht gefunden"});
  await q("insert into document_delivery_events(invoice_id,event_type,metadata) values($1,'viewed',$2)",[r[0].id,"portal"]);
  res.json(r[0]);
});
app.get("/api/portal/ddt/:id",portalAuth39,async(req,res)=>{
  const r=await q(`select d.* from delivery_documents d join trips t on t.id=d.trip_id where d.id=$1 and t.customer_id=$2`,
    [req.params.id,req.portal.customer_id]);
  if(!r[0])return res.status(404).json({error:"DDT nicht gefunden"});
  await q("insert into document_delivery_events(delivery_document_id,event_type,metadata) values($1,'viewed',$2)",[r[0].id,"portal"]);
  res.json(r[0]);
});
app.post("/api/portal/invoices/:id/paid-notice",portalAuth39,async(req,res)=>{
  const r=await q("select * from invoices where id=$1 and customer_id=$2",[req.params.id,req.portal.customer_id]);
  if(!r[0])return res.status(404).json({error:"Rechnung nicht gefunden"});
  await q("insert into document_delivery_events(invoice_id,event_type,metadata) values($1,'payment_notice',$2)",[r[0].id,String(req.body.note||"").slice(0,1000)]);
  res.json({ok:true});
});


// V40: email delivery

let mailer40=null;
try{
  mailer40=smtpTransport();
}catch(e){console.warn("SMTP module unavailable; email remains queued.",e.message)}

async function queueCustomerEmail40({customerId,invoiceId=null,ddtId=null,to,subject,html}){
  if(!to) throw new Error("Kunden-E-Mail fehlt");
  const r=await q(`insert into email_outbox(customer_id,invoice_id,delivery_document_id,recipient,subject,body_html)
    values($1,$2,$3,$4,$5,$6) returning *`,[customerId,invoiceId,ddtId,to,subject,html]);
  return r[0];
}
async function processEmail40(){
  const rows=await q(`select * from email_outbox where status in ('Queued','Retry') and attempts<5 order by queued_at limit 10`);
  for(const m of rows){
    if(!mailer40){
      await q("update email_outbox set status='Queued',last_error=$2 where id=$1",[m.id,"SMTP not configured"]);
      continue;
    }
    try{
      smtpCfg=loadSmtpConfig(); mailer40=smtpTransport();
      if(!mailer40) throw new Error("Gmail SMTP nicht konfiguriert");
      await mailer40.sendMail({from:smtpCfg.from||smtpCfg.user,to:m.recipient,subject:m.subject,html:m.body_html});
      await q("update email_outbox set status='Sent',sent_at=now(),attempts=attempts+1,last_error=null where id=$1",[m.id]);
      if(m.invoice_id) await q("update invoices set sent_at=now() where id=$1",[m.invoice_id]);
      if(m.delivery_document_id) await q("update delivery_documents set sent_at=now() where id=$1",[m.delivery_document_id]);
      await q("insert into document_delivery_events(invoice_id,delivery_document_id,event_type,recipient) values($1,$2,'sent',$3)",[m.invoice_id,m.delivery_document_id,m.recipient]);
    }catch(e){
      await q("update email_outbox set status='Retry',attempts=attempts+1,last_error=$2 where id=$1",[m.id,String(e.message).slice(0,1000)]);
    }
  }
}
// E-Mail-Versand deaktiviert: Emergency Delivery enthält keine Mail-Funktion mehr.

app.post("/api/invoices/:id/send",auth,roles("Admin","Dispatcher","Accounting"),async(req,res)=>{
  try{
    const x=(await q(`select i.*,c.id customer_id,c.email,c.company from invoices i left join customers c on c.id=i.customer_id where i.id=$1`,[req.params.id]))[0];
    if(!x)return res.status(404).json({error:"Rechnung nicht gefunden"});
    if(!x.email)return res.status(400).json({error:"Kunden-E-Mail fehlt"});
    const body=`<p>Guten Tag ${String(x.company||"").replace(/[<>]/g,"")},</p><p>anbei erhalten Sie die Rechnung <b>${x.invoice_number}</b> über ${Number(x.gross).toFixed(2)} EUR.</p><p>Sie können Rechnung und Zustellbeleg auch über das Kundenportal abrufen.</p><p>Emergency Delivery</p>`;
    const m=await queueCustomerEmail40({customerId:x.customer_id,invoiceId:x.id,to:x.email,subject:"Rechnung "+x.invoice_number+" – Emergency Delivery",html:body});
    await audit(req,"INVOICE_EMAIL_QUEUED",x.invoice_number+" -> "+x.email);
    res.json(m);
  }catch(e){res.status(500).json({error:e.message})}
});
app.post("/api/trips/:id/send-documents",auth,roles("Admin","Dispatcher","Accounting"),async(req,res)=>{
  try{
    const x=(await q(`select t.id,t.trip_number,t.customer_id,c.email,c.company,i.id invoice_id,i.invoice_number,d.id ddt_id,d.document_number
      from trips t left join customers c on c.id=t.customer_id left join invoices i on i.trip_id=t.id left join delivery_documents d on d.trip_id=t.id
      where t.id=$1`,[req.params.id]))[0];
    if(!x)return res.status(404).json({error:"Tour nicht gefunden"});
    if(!x.email)return res.status(400).json({error:"Kunden-E-Mail fehlt"});
    const body=`<p>Guten Tag ${String(x.company||"").replace(/[<>]/g,"")},</p><p>die Transporttour <b>${x.trip_number}</b> ist abgeschlossen.</p><p>Rechnung: ${x.invoice_number||"noch nicht vorhanden"}<br>Lieferschein: ${x.document_number||"noch nicht vorhanden"}</p><p>Die Dokumente stehen zusätzlich im Kundenportal bereit.</p><p>Emergency Delivery</p>`;
    const m=await queueCustomerEmail40({customerId:x.customer_id,invoiceId:x.invoice_id,ddtId:x.ddt_id,to:x.email,subject:"Transportdokumente "+x.trip_number+" – Emergency Delivery",html:body});
    await audit(req,"TRIP_DOCUMENTS_EMAIL_QUEUED",x.trip_number+" -> "+x.email);
    res.json(m);
  }catch(e){res.status(500).json({error:e.message})}
});
app.get("/api/email/settings",auth,roles("Admin"),async(req,res)=>{
  smtpCfg=loadSmtpConfig();
  res.json({host:smtpCfg.host||"smtp.gmail.com",port:Number(smtpCfg.port||587),secure:!!smtpCfg.secure,user:smtpCfg.user||"",from:smtpCfg.from||smtpCfg.user||"",configured:!!(smtpCfg.user&&smtpCfg.pass)});
});
app.patch("/api/email/settings",auth,roles("Admin"),async(req,res)=>{
  try{
    const b=req.body||{};
    const host=String(b.host||"smtp.gmail.com").trim(), port=Number(b.port||587), secure=!!b.secure, user=String(b.user||"").trim(), from=String(b.from||user).trim();
    const pass=String(b.pass||"").replace(/\s+/g,"");
    if(!host||!user) return res.status(400).json({error:"SMTP-Server und Gmail-Adresse sind erforderlich."});
    if(![465,587].includes(port)) return res.status(400).json({error:"Für Gmail bitte Port 465 oder 587 verwenden."});
    smtpCfg={host,port,secure,user,from,pass:pass||smtpCfg.pass||""};
    saveSmtpConfig(smtpCfg); mailer40=smtpTransport();
    res.json({ok:true,configured:!!smtpCfg.pass,message:"Gmail SMTP-Einstellungen gespeichert."});
  }catch(e){res.status(500).json({error:e.message})}
});
app.post("/api/email/test-smtp",auth,roles("Admin"),async(req,res)=>{
  try{
    smtpCfg=loadSmtpConfig();
    if(!smtpCfg.user||!smtpCfg.pass)return res.status(400).json({error:"Gmail-Adresse und App-Passwort fehlen."});
    const transporter=smtpTransport();
    await transporter.verify();
    res.json({ok:true,message:"Gmail SMTP-Verbindung erfolgreich geprüft."});
  }catch(e){
    const raw=String(e?.message||e);
    const hint=(/Invalid login|Username and Password not accepted|535|BadCredentials|authentication/i.test(raw))
      ? " Gmail akzeptiert hier kein normales Kontopasswort. Bitte unter Google-Konto → Sicherheit → Bestätigung in zwei Schritten ein 16-stelliges App-Passwort erstellen und dieses hier eintragen."
      : "";
    res.status(502).json({error:"Gmail SMTP-Verbindung fehlgeschlagen: "+raw+hint});
  }
});

app.post("/api/email/send-direct",auth,roles("Admin","Dispatcher","Accounting"),async(req,res)=>{
  try{
    smtpCfg=loadSmtpConfig();
    mailer40=smtpTransport();
    if(!mailer40) return res.status(503).json({error:"Gmail ist noch nicht eingerichtet. Bitte unter E-Mail → Gmail SMTP die Gmail-Adresse und ein Google-App-Passwort hinterlegen."});
    const b=req.body||{}; const to=String(b.to||'').trim(); const subject=String(b.subject||'').trim(); const body=String(b.body||'');
    if(!to||!subject||!body)return res.status(400).json({error:"Empfänger, Betreff und Nachricht sind erforderlich"});
    const validTo=to.split(',').map(x=>x.trim()).filter(Boolean); if(!validTo.length)return res.status(400).json({error:"Ungültiger Empfänger"});
    const attachments=[];
    if(b.invoiceId){
      const inv=(await q(`select i.*,c.company customer_company,c.vat_id customer_vat,t.trip_number from invoices i left join customers c on c.id=i.customer_id left join trips t on t.id=i.trip_id where i.id=$1`,[b.invoiceId]))[0];
      if(inv){const pdf=await v87BuildInvoicePdf(inv);attachments.push({filename:`${inv.invoice_number}.pdf`,content:pdf});}
    }
    if(b.tripId){
      const trip=(await q(`select t.*,c.company customer_company,c.vat_id customer_vat,u.name driver_name,v.name vehicle_name,v.plate from trips t left join customers c on c.id=t.customer_id left join users u on u.id=t.driver_id left join vehicles v on v.id=t.vehicle_id where t.id=$1`,[b.tripId]))[0];
      const ddt=trip?(await q(`select * from delivery_documents where trip_id=$1 order by issued_at desc limit 1`,[b.tripId]))[0]:null;
      if(trip&&ddt){const stops=await q(`select * from trip_stops where trip_id=$1 order by dispatch_position nulls last,stop_order`,[b.tripId]);const pdf=await v87BuildDdtPdf(trip,stops,ddt);attachments.push({filename:`${ddt.document_number}.pdf`,content:pdf});}
    }
    const info=await mailer40.sendMail({from:smtpCfg.from||smtpCfg.user,to:validTo.join(', '),cc:String(b.cc||'').trim()||undefined,subject,html:body.replace(/\n/g,'<br>'),attachments});
    let customerId=b.customerId||null, invoiceId=b.invoiceId||null, ddtId=null;
    if(b.tripId){const x=(await q(`select id from delivery_documents where trip_id=$1 order by issued_at desc limit 1`,[b.tripId]))[0];ddtId=x?.id||null;}
    await q(`insert into email_outbox(customer_id,invoice_id,delivery_document_id,recipient,subject,body_html,status,sent_at,attempts) values($1,$2,$3,$4,$5,$6,'Sent',now(),1)`,[customerId,invoiceId,ddtId,validTo.join(', '),subject,body]);
    await audit(req,'EMAIL_SENT_DIRECT',validTo.join(', ')+' · '+subject);
    res.json({ok:true,message:"E-Mail erfolgreich gesendet.",messageId:info.messageId});
  }catch(e){res.status(500).json({error:e.message})}
});

app.get("/api/email/outbox",auth,roles("Admin","Dispatcher","Accounting"),async(req,res)=>{
  try{res.json(await q(`select e.*,c.company from email_outbox e left join customers c on c.id=e.customer_id order by e.queued_at desc limit 100`))}
  catch(e){res.status(500).json({error:e.message})}
});
app.post("/api/email/outbox/:id/retry",auth,roles("Admin","Dispatcher","Accounting"),async(req,res)=>{
  try{const r=await q("update email_outbox set status='Retry',last_error=null where id=$1 returning *",[req.params.id]);if(!r[0])return res.status(404).json({error:"E-Mail nicht gefunden"});res.json(r[0])}
  catch(e){res.status(500).json({error:e.message})}
});


// V41: employee administration

app.get("/api/users",auth,roles("Admin"),async(req,res)=>{
  try{res.json(await q(`select id,username,name,role,email,phone,active,must_change_password,created_at,last_seen_at from users order by name`))}
  catch(e){res.status(500).json({error:e.message})}
});
app.patch("/api/users/:id",auth,roles("Admin"),async(req,res)=>{
  try{
    const allowed=["name","role","email","phone","active","must_change_password"];
    const a=Object.keys(req.body).filter(k=>allowed.includes(k));
    if(!a.length)return res.status(400).json({error:"Keine Änderungen"});
    const vals=a.map(k=>req.body[k]), set=a.map((k,i)=>`${k}=$${i+2}`).join(",");
    const r=await q(`update users set ${set} where id=$1 returning id,username,name,role,email,phone,active,must_change_password`,[req.params.id,...vals]);
    if(!r[0])return res.status(404).json({error:"Benutzer nicht gefunden"});
    await audit(req,"USER_UPDATED",r[0].username);res.json(r[0]);
  }catch(e){res.status(400).json({error:e.message})}
});
app.post("/api/users/:id/password",auth,async(req,res)=>{
  try{
    if(req.user.role!=="Admin"&&req.user.id!==req.params.id)return res.status(403).json({error:"Not permitted"});
    const pw=String(req.body.password||""); if(pw.length<8)return res.status(400).json({error:"Passwort mindestens 8 Zeichen"});
    const hash=await bcrypt.hash(pw,12);
    const r=await q("update users set password_hash=$2,must_change_password=false where id=$1 returning username",[req.params.id,hash]);
    if(!r[0])return res.status(404).json({error:"Benutzer nicht gefunden"});
    await audit(req,"PASSWORD_CHANGED",r[0].username);res.json({ok:true});
  }catch(e){res.status(500).json({error:e.message})}
});
app.post("/api/users",auth,roles("Admin"),async(req,res)=>{
  try{
    const username=String(req.body.username||"").trim(), name=String(req.body.name||"").trim(), role=String(req.body.role||"Driver");
    const pw=String(req.body.password||""); if(!username||!name||pw.length<8)return res.status(400).json({error:"Username, Name und Passwort (8+) erforderlich"});
    if(!["Admin","Dispatcher","Driver","Accounting"].includes(role))return res.status(400).json({error:"Ungültige Rolle"});
    const hash=await bcrypt.hash(pw,12);
    const r=await q(`insert into users(username,name,role,password_hash,email,phone,must_change_password) values($1,$2,$3,$4,$5,$6,true)
      returning id,username,name,role,email,phone,active,must_change_password`,[username,name,role,hash,req.body.email||null,req.body.phone||null]);
    await audit(req,"USER_CREATED",username);res.json(r[0]);
  }catch(e){res.status(400).json({error:e.message})}
});
app.post("/api/employee-time",auth,async(req,res)=>{
  try{
    const target=req.user.role==="Admin"&&req.body.user_id?req.body.user_id:req.user.id;
    const type=String(req.body.entry_type||"");
    if(!["clock_in","clock_out","break_start","break_end"].includes(type))return res.status(400).json({error:"Ungültiger Zeittyp"});
    const r=await q(`insert into employee_time_entries(user_id,entry_type,source,note) values($1,$2,$3,$4) returning *`,
      [target,type,String(req.body.source||"web").slice(0,30),String(req.body.note||"").slice(0,500)]);
    await audit(req,"TIME_ENTRY",type+" / "+target);res.json(r[0]);
  }catch(e){res.status(500).json({error:e.message})}
});
app.get("/api/employee-time",auth,async(req,res)=>{
  try{
    const target=req.user.role==="Admin"&&req.query.user_id?req.query.user_id:req.user.id;
    const rows=await q(`select e.*,u.name,u.role from employee_time_entries e join users u on u.id=e.user_id
      where e.user_id=$1 and e.occurred_at>now()-interval '31 days' order by e.occurred_at desc`,[target]);
    res.json(rows);
  }catch(e){res.status(500).json({error:e.message})}
});


// V42: workforce planning

function minutes42(a,b){if(!a||!b)return 0;const [ah,am]=String(a).slice(0,5).split(":").map(Number),[bh,bm]=String(b).slice(0,5).split(":").map(Number);return Math.max(0,(bh*60+bm)-(ah*60+am));}
app.get("/api/workforce/overview",auth,roles("Admin","Dispatcher","Accounting"),async(req,res)=>{
  try{
    const users=await q(`select id,name,role,active from users where role in('Admin','Dispatcher','Driver','Accounting') order by name`);
    const abs=await q(`select a.*,u.name from employee_absences a join users u on u.id=a.user_id
      where a.end_date>=current_date-interval '30 days' and a.start_date<=current_date+interval '60 days' order by a.start_date`);
    const shifts=await q(`select s.*,u.name from driver_shifts s join users u on u.id=s.driver_id
      where s.shift_date between current_date-interval '7 days' and current_date+interval '30 days' order by s.shift_date,u.name`);
    res.json({users,absences:abs,shifts});
  }catch(e){res.status(500).json({error:e.message})}
});
app.post("/api/workforce/absence",auth,roles("Admin"),async(req,res)=>{
  try{
    const r=await q(`insert into employee_absences(user_id,start_date,end_date,absence_type,note,status)
      values($1,$2,$3,$4,$5,$6) returning *`,
      [req.body.user_id,req.body.start_date,req.body.end_date,req.body.absence_type,String(req.body.note||"").slice(0,1000),String(req.body.status||"planned")]);
    await audit(req,"ABSENCE_CREATED",r[0].user_id+" "+r[0].start_date+"-"+r[0].end_date);res.json(r[0]);
  }catch(e){res.status(400).json({error:e.message})}
});
app.get("/api/workforce/week-plan/:userId",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{res.json(await q("select * from weekly_work_plans where user_id=$1 order by weekday",[req.params.userId]))}
  catch(e){res.status(500).json({error:e.message})}
});
app.post("/api/workforce/week-plan",auth,roles("Admin"),async(req,res)=>{
  try{
    const r=await q(`insert into weekly_work_plans(user_id,weekday,start_time,end_time,break_minutes,active)
      values($1,$2,$3,$4,$5,$6)
      on conflict(user_id,weekday) do update set start_time=excluded.start_time,end_time=excluded.end_time,
      break_minutes=excluded.break_minutes,active=excluded.active returning *`,
      [req.body.user_id,req.body.weekday,req.body.start_time||null,req.body.end_time||null,Number(req.body.break_minutes||0),req.body.active!==false]);
    res.json(r[0]);
  }catch(e){res.status(400).json({error:e.message})}
});
app.post("/api/workforce/validate-day",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const date=req.body.date||new Date().toISOString().slice(0,10);
    const drivers=await q(`select u.id,u.name,ds.start_at,ds.end_at,ds.break_minutes,
      coalesce(ds.planned_minutes,0) planned_minutes
      from users u left join driver_shifts ds on ds.driver_id=u.id and ds.shift_date=$1
      where u.role='Driver' and u.active=true order by u.name`,[date]);
    const abs=await q(`select user_id,absence_type from employee_absences where start_date<= $1 and end_date>= $1 and status<>'cancelled'`,[date]);
    const absent=new Map(abs.map(x=>[x.user_id,x.absence_type]));
    const result=drivers.map(d=>{
      const available=d.start_at&&d.end_at?Math.max(0,Math.round((new Date(d.end_at)-new Date(d.start_at))/60000)-Number(d.break_minutes||0)):0;
      return {...d,absence:absent.get(d.id)||null,available_minutes:available,remaining_minutes:available-Number(d.planned_minutes||0),
        over_capacity:Number(d.planned_minutes||0)>available};
    });
    res.json({date,drivers:result});
  }catch(e){res.status(500).json({error:e.message})}
});


// V43: vehicle management

app.get("/api/vehicles/manage",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const vehicles=await q(`select * from vehicles order by name`);
    const maint=await q(`select m.*,v.name vehicle_name from vehicle_maintenance m join vehicles v on v.id=m.vehicle_id
      where m.status<>'completed' order by m.due_date nulls last,m.due_odometer_km nulls last`);
    const damages=await q(`select d.*,v.name vehicle_name from vehicle_damage d join vehicles v on v.id=d.vehicle_id where d.resolved_at is null order by d.reported_at desc`);
    const costs=await q(`select c.*,v.name vehicle_name from vehicle_costs c join vehicles v on v.id=c.vehicle_id order by c.cost_date desc limit 100`);
    res.json({vehicles,maintenance:maint,damages,costs});
  }catch(e){res.status(500).json({error:e.message})}
});
app.patch("/api/vehicles/:id",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const allowed=["name","plate","active","vin","make","model","year","odometer_km","insurance_until","inspection_until","registration_until"];
    const a=Object.keys(req.body).filter(k=>allowed.includes(k)); if(!a.length)return res.status(400).json({error:"Keine Änderungen"});
    const set=a.map((k,i)=>`${k}=$${i+2}`).join(","), vals=a.map(k=>req.body[k]);
    const r=await q(`update vehicles set ${set} where id=$1 returning *`,[req.params.id,...vals]); if(!r[0])return res.status(404).json({error:"Fahrzeug nicht gefunden"});
    await audit(req,"VEHICLE_UPDATED",r[0].name);res.json(r[0]);
  }catch(e){res.status(400).json({error:e.message})}
});
app.post("/api/vehicles",auth,roles("Admin"),async(req,res)=>{
  try{
    const r=await q(`insert into vehicles(name,plate,vin,make,model,year,odometer_km,insurance_until,inspection_until,registration_until)
      values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) returning *`,
      [req.body.name,req.body.plate,req.body.vin||null,req.body.make||null,req.body.model||null,req.body.year||null,Number(req.body.odometer_km||0),req.body.insurance_until||null,req.body.inspection_until||null,req.body.registration_until||null]);
    await audit(req,"VEHICLE_CREATED",r[0].name);res.json(r[0]);
  }catch(e){res.status(400).json({error:e.message})}
});
app.delete("/api/vehicles/:id",auth,roles("Admin"),async(req,res)=>{
  try{
    const used=await q("select count(*)::int n from trips where vehicle_id=$1",[req.params.id]);
    if(Number(used[0]?.n||0)>0)return res.status(409).json({error:"Fahrzeug kann nicht gelöscht werden, weil bereits Touren zugeordnet sind. Bitte deaktivieren."});
    const r=await q("delete from vehicles where id=$1 returning id,name",[req.params.id]);
    if(!r.length)return res.status(404).json({error:"Fahrzeug nicht gefunden"});
    await audit(req,"VEHICLE_DELETED",r[0].name);res.json({ok:true});
  }catch(e){res.status(400).json({error:e.message})}
});
app.post("/api/vehicles/:id/maintenance",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const r=await q(`insert into vehicle_maintenance(vehicle_id,maintenance_type,due_date,due_odometer_km,cost_net,provider,note,status)
      values($1,$2,$3,$4,$5,$6,$7,'planned') returning *`,
      [req.params.id,req.body.maintenance_type,req.body.due_date||null,req.body.due_odometer_km||null,Number(req.body.cost_net||0),req.body.provider||null,String(req.body.note||"").slice(0,1000)]);
    res.json(r[0]);
  }catch(e){res.status(400).json({error:e.message})}
});
app.post("/api/vehicles/maintenance/:id/complete",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const r=await q(`update vehicle_maintenance set status='completed',completed_at=now(),completed_odometer_km=$2 where id=$1 returning *`,
      [req.params.id,req.body.odometer_km||null]); if(!r[0])return res.status(404).json({error:"Wartung nicht gefunden"});res.json(r[0]);
  }catch(e){res.status(500).json({error:e.message})}
});
app.post("/api/vehicles/:id/damage",auth,roles("Admin","Dispatcher","Driver"),async(req,res)=>{
  try{
    const p=String(req.body.photo_data||""); if(p.length>2_000_000)return res.status(413).json({error:"Foto zu groß"});
    const r=await q(`insert into vehicle_damage(vehicle_id,severity,description,photo_data) values($1,$2,$3,$4) returning *`,
      [req.params.id,req.body.severity||"minor",String(req.body.description||"").slice(0,2000),p||null]);
    await audit(req,"VEHICLE_DAMAGE_REPORTED",req.params.id);res.json(r[0]);
  }catch(e){res.status(400).json({error:e.message})}
});
app.post("/api/vehicles/:id/cost",auth,roles("Admin","Accounting","Dispatcher"),async(req,res)=>{
  try{
    const r=await q(`insert into vehicle_costs(vehicle_id,cost_date,cost_type,amount_net,note) values($1,$2,$3,$4,$5) returning *`,
      [req.params.id,req.body.cost_date||new Date().toISOString().slice(0,10),req.body.cost_type,Number(req.body.amount_net||0),String(req.body.note||"").slice(0,1000)]);
    res.json(r[0]);
  }catch(e){res.status(400).json({error:e.message})}
});


// V44: vehicle alerts

async function checkVehicleAlerts44(){
  const vs=await q("select * from vehicles where active=true");
  const today=new Date(); today.setHours(0,0,0,0);
  for(const v of vs){
    const checks=[
      ["insurance_until",v.insurance_until,"Versicherung"],
      ["inspection_until",v.inspection_until,"HU/Revision"],
      ["registration_until",v.registration_until,"Zulassung"]
    ];
    for(const [field,dateVal,label] of checks){
      if(!dateVal)continue;
      const d=new Date(dateVal+"T00:00:00"), days=Math.ceil((d-today)/86400000);
      if(days<=30){
        const sev=days<0?"critical":days<=7?"critical":"warning";
        const msg=days<0?`${label} abgelaufen seit ${Math.abs(days)} Tagen`:`${label} fällig in ${days} Tagen`;
        const exists=await q(`select id from vehicle_alerts where vehicle_id=$1 and alert_type=$2 and acknowledged=false
          and created_at>now()-interval '7 days'`,[v.id,field]);
        if(!exists[0])await q(`insert into vehicle_alerts(vehicle_id,alert_type,severity,message,due_date) values($1,$2,$3,$4,$5)`,
          [v.id,field,sev,msg,dateVal]);
      }
    }
    const ms=await q(`select * from vehicle_maintenance where vehicle_id=$1 and status<>'completed' and
      ((due_date is not null and due_date<=current_date+30) or (due_odometer_km is not null and due_odometer_km<= $2+500))`,[v.id,Number(v.odometer_km||0)]);
    for(const m of ms){
      const byKm=m.due_odometer_km!=null && Number(m.due_odometer_km)<=Number(v.odometer_km||0)+500;
      const byDate=m.due_date && new Date(m.due_date+"T00:00:00")<=new Date(Date.now()+30*86400000);
      if(byKm||byDate){
        const exists=await q(`select id from vehicle_alerts where vehicle_id=$1 and alert_type='maintenance' and message like $2 and acknowledged=false
          and created_at>now()-interval '7 days'`,[v.id,"%"+String(m.maintenance_type)+"%"]);
        if(!exists[0])await q(`insert into vehicle_alerts(vehicle_id,alert_type,severity,message,due_date,due_odometer_km)
          values($1,'maintenance','warning',$2,$3,$4)`,[v.id,`Wartung fällig: ${m.maintenance_type}`,m.due_date,m.due_odometer_km]);
      }
    }
  }
}
setInterval(()=>checkVehicleAlerts44().catch(e=>console.error("vehicle alerts",e)),3600000);
app.get("/api/vehicles/alerts",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{await checkVehicleAlerts44();res.json(await q(`select a.*,v.name vehicle_name,v.plate from vehicle_alerts a join vehicles v on v.id=a.vehicle_id
    where a.acknowledged=false order by case a.severity when 'critical' then 1 else 2 end,a.created_at desc`))}
  catch(e){res.status(500).json({error:e.message})}
});
app.post("/api/vehicles/alerts/:id/ack",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{const r=await q("update vehicle_alerts set acknowledged=true,acknowledged_at=now() where id=$1 returning *",[req.params.id]);if(!r[0])return res.status(404).json({error:"Warnung nicht gefunden"});await audit(req,"VEHICLE_ALERT_ACK",r[0].message);res.json(r[0])}
  catch(e){res.status(500).json({error:e.message})}
});


// V45: economics

app.post("/api/trips/:id/cost",auth,roles("Admin","Dispatcher","Accounting"),async(req,res)=>{
  try{
    const r=await q(`insert into trip_costs(trip_id,cost_type,amount_net,cost_date,note) values($1,$2,$3,$4,$5) returning *`,
      [req.params.id,req.body.cost_type,Number(req.body.amount_net||0),req.body.cost_date||new Date().toISOString().slice(0,10),String(req.body.note||"").slice(0,1000)]);
    res.json(r[0]);
  }catch(e){res.status(400).json({error:e.message})}
});
app.post("/api/vehicles/:id/fuel",auth,roles("Admin","Dispatcher","Accounting"),async(req,res)=>{
  try{
    const liters=Number(req.body.liters||0), price=Number(req.body.price_net||0);
    if(liters<0||price<0)return res.status(400).json({error:"Ungültige Werte"});
    const r=await q(`insert into fuel_entries(vehicle_id,entry_date,liters,price_net,odometer_km,note)
      values($1,$2,$3,$4,$5,$6) returning *`,
      [req.params.id,req.body.entry_date||new Date().toISOString().slice(0,10),liters,price,req.body.odometer_km||null,String(req.body.note||"").slice(0,1000)]);
    if(req.body.odometer_km!=null)await q("update vehicles set odometer_km=greatest(odometer_km,$2) where id=$1",[req.params.id,Number(req.body.odometer_km)]);
    res.json(r[0]);
  }catch(e){res.status(400).json({error:e.message})}
});
app.get("/api/reports/economics",auth,roles("Admin","Dispatcher","Accounting"),async(req,res)=>{
  try{
    const from=req.query.from||new Date(new Date().setDate(new Date().getDate()-30)).toISOString().slice(0,10);
    const to=req.query.to||new Date().toISOString().slice(0,10);
    const trips=await q(`select t.id,t.trip_number,t.price_net,t.route_distance_km,t.weight_kg,t.status,t.planning_date,
      c.company customer_company,v.name vehicle_name,
      coalesce((select sum(amount_net) from trip_costs tc where tc.trip_id=t.id and tc.cost_date between $1 and $2),0) trip_cost
      from trips t left join customers c on c.id=t.customer_id left join vehicles v on v.id=t.vehicle_id
      where coalesce(t.planning_date,t.created_at::date) between $1 and $2 order by coalesce(t.planning_date,t.created_at::date) desc`,[from,to]);
    const fuel=await q(`select coalesce(sum(liters),0) liters,coalesce(sum(liters*price_net),0) amount from fuel_entries where entry_date between $1 and $2`,[from,to]);
    const vehicle=await q(`select coalesce(sum(amount_net),0) amount from vehicle_costs where cost_date between $1 and $2`,[from,to]);
    const revenue=trips.reduce((a,x)=>a+Number(x.price_net||0),0), tripCosts=trips.reduce((a,x)=>a+Number(x.trip_cost||0),0);
    const totalCost=tripCosts+Number(fuel[0].amount)+Number(vehicle[0].amount), margin=revenue-totalCost;
    res.json({from,to,summary:{revenue,trip_costs:tripCosts,fuel_costs:Number(fuel[0].amount),vehicle_costs:Number(vehicle[0].amount),total_cost:totalCost,margin},trips,fuel:fuel[0]});
  }catch(e){res.status(500).json({error:e.message})}
});


// V46: customer pricing

app.get("/api/pricing/rules",auth,roles("Admin","Dispatcher","Accounting"),async(req,res)=>{
  try{res.json(await q(`select r.*,c.company customer_company from customer_price_rules r left join customers c on c.id=r.customer_id
    where r.active=true order by c.company nulls first,r.min_weight_kg`))}
  catch(e){res.status(500).json({error:e.message})}
});
app.post("/api/pricing/rules",auth,roles("Admin","Dispatcher","Accounting"),async(req,res)=>{
  try{
    const r=await q(`insert into customer_price_rules(customer_id,name,min_weight_kg,max_weight_kg,base_price,price_per_kg,minimum_price,urgent_surcharge,active)
      values($1,$2,$3,$4,$5,$6,$7,$8,$9) returning *`,
      [req.body.customer_id||null,req.body.name,Number(req.body.min_weight_kg||0),Number(req.body.max_weight_kg||1000),
       Number(req.body.base_price||0),Number(req.body.price_per_kg||0),Number(req.body.minimum_price||0),Number(req.body.urgent_surcharge||0),req.body.active!==false]);
    res.json(r[0]);
  }catch(e){res.status(400).json({error:e.message})}
});
app.post("/api/pricing/calculate",auth,roles("Admin","Dispatcher","Accounting"),async(req,res)=>{
  try{
    const kg=Math.max(0,Number(req.body.weight_kg||0)); if(kg>1000)return res.status(400).json({error:"Maximal 1000 KG"});
    const urgent=String(req.body.priority||"normal")==="urgent";
    const customer=req.body.customer_id||null;
    let rules=await q(`select * from customer_price_rules where active=true and (customer_id=$1 or customer_id is null)
      and min_weight_kg<=$2 and max_weight_kg>=$2 order by case when customer_id=$1 then 0 else 1 end,min_weight_kg desc`,[customer,kg]);
    let r=rules[0];
    if(!r) r=(await q(`select * from order_pricing where active=true and min_weight_kg<=$1 and max_weight_kg>=$1
      order by min_weight_kg desc limit 1`,[kg]))[0];
    if(!r)return res.json({price_net:0,source:"none",message:"Keine Preisregel"});
    const base=Number(r.base_price||0), per=Number(r.price_per_kg||0), min=Number(r.minimum_price||0);
    const surcharge=urgent?Number(r.urgent_surcharge||0):0;
    const raw=base+kg*per+surcharge, price=Math.max(min,raw);
    res.json({price_net:Number(price.toFixed(2)),base,kg_price:Number((kg*per).toFixed(2)),urgent_surcharge:surcharge,minimum_price:min,source:r.customer_id?"customer":"default"});
  }catch(e){res.status(500).json({error:e.message})}
});


// V47: order capture

app.get("/api/orders",auth,roles("Admin","Dispatcher","Accounting"),async(req,res)=>{
  try{res.json(await q(`select o.*,c.company customer_company from orders o left join customers c on c.id=o.customer_id
    order by o.created_at desc limit 200`))}
  catch(e){res.status(500).json({error:e.message})}
});
app.post("/api/orders/create",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const kg=Math.max(0,Number(req.body.weight_kg||0)); if(kg>1000)return res.status(400).json({error:"Maximal 1000 KG"});
    if(!req.body.customer_id||!req.body.delivery_address)return res.status(400).json({error:"Kunde und Lieferadresse erforderlich"});
    const priceRes=await q(`select * from customer_price_rules where active=true and (customer_id=$1 or customer_id is null)
      and min_weight_kg<=$2 and max_weight_kg>=$2 order by case when customer_id=$1 then 0 else 1 end,min_weight_kg desc`,[req.body.customer_id,kg]);
    let pr=priceRes[0];
    if(!pr)pr=(await q(`select * from order_pricing where active=true and min_weight_kg<=$1 and max_weight_kg>=$1 order by min_weight_kg desc limit 1`,[kg]))[0];
    const urgent=String(req.body.priority||"normal")==="urgent";
    let price=Number(req.body.price_net||0);
    if(pr){price=Math.max(Number(pr.minimum_price||0),Number(pr.base_price||0)+kg*Number(pr.price_per_kg||0)+(urgent?Number(pr.urgent_surcharge||0):0));}
    const ref="ORD-"+Date.now().toString(36).toUpperCase();
    const cols=["customer_id","reference","pickup_address","pickup_city","delivery_address","delivery_city","weight_kg","pieces","customer_reference","priority","requested_date","time_window_start","time_window_end","estimated_service_min","price_net","status"];
    const vals=[req.body.customer_id,ref,req.body.pickup_address||"",req.body.pickup_city||"",req.body.delivery_address,req.body.delivery_city||"",kg,Math.max(1,parseInt(req.body.pieces||1,10)),req.body.customer_reference||"",req.body.priority||"normal",req.body.requested_date||null,req.body.time_window_start||null,req.body.time_window_end||null,Math.max(1,parseInt(req.body.estimated_service_min||15,10)),price,"new"];
    const ph=vals.map((_,i)=>"$"+(i+1)).join(",");
    const r=await q(`insert into orders(${cols.join(",")}) values(${ph}) returning *`,vals);
    await audit(req,"ORDER_CREATED",ref);res.json(r[0]);
  }catch(e){res.status(400).json({error:e.message})}
});
app.post("/api/orders/:id/price-preview",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const o=(await q("select * from orders where id=$1",[req.params.id]))[0];if(!o)return res.status(404).json({error:"Auftrag nicht gefunden"});
    const kg=Number(req.body.weight_kg??o.weight_kg),priority=req.body.priority||o.priority;
    const r=await q(`select * from customer_price_rules where active=true and (customer_id=$1 or customer_id is null)
      and min_weight_kg<=$2 and max_weight_kg>=$2 order by case when customer_id=$1 then 0 else 1 end,min_weight_kg desc`,[o.customer_id,kg]);
    const p=r[0];if(!p)return res.json({price_net:0});
    const price=Math.max(Number(p.minimum_price||0),Number(p.base_price||0)+kg*Number(p.price_per_kg||0)+(priority==="urgent"?Number(p.urgent_surcharge||0):0));
    res.json({price_net:Number(price.toFixed(2)),rule:p.name});
  }catch(e){res.status(500).json({error:e.message})}
});



// V48 automatic dispatch from open orders to the two transporter slots
app.get("/api/planning/open-orders",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const r=await q(`select o.*,c.company customer_company from orders o left join customers c on c.id=o.customer_id
      where coalesce(o.status,'new') in ('new','planned') and o.planned_trip_id is null
      order by case o.priority when 'urgent' then 0 when 'high' then 1 else 2 end,o.requested_date nulls last,o.created_at`);
    res.json(r)
  }catch(e){res.status(500).json({error:e.message})}
});
app.post("/api/planning/auto-dispatch-orders",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const date=req.body.date || new Date().toISOString().slice(0,10);
    const orders=(await q(`select o.*,c.company customer_company from orders o left join customers c on c.id=o.customer_id
      where coalesce(o.status,'new') in ('new','planned') and o.planned_trip_id is null
      and (o.requested_date is null or o.requested_date=$1)
      order by case o.priority when 'urgent' then 0 when 'high' then 1 else 2 end,o.time_window_start nulls last,o.created_at`,[date]));
    const vehicles=await q(`select * from vehicles where active=true order by name limit 2`);
    const drivers=await q(`select * from users where role='Driver' and active=true order by name limit 2`);
    if(!vehicles.length || !drivers.length) return res.status(400).json({error:"Mindestens ein aktives Fahrzeug und Fahrer werden benötigt"});
    const slots=[0,1].map(i=>({vehicle:vehicles[i%vehicles.length],driver:drivers[i%drivers.length],orders:[],kg:0,minutes:0}));
    const skipped=[];
    for(const o of orders){
      const kg=Number(o.weight_kg||0), service=Number(o.estimated_service_min||15);
      let candidates=slots.filter(x=>x.kg+kg<=1000);
      if(o.time_window_start) candidates=candidates.sort((a,b)=>a.minutes-b.minutes);
      else candidates=candidates.sort((a,b)=>a.kg-b.kg);
      if(!candidates.length){skipped.push({id:o.id,reference:o.reference,reason:"Kapazitätslimit 1000 KG"});continue}
      const slot=candidates[0]; slot.orders.push(o); slot.kg+=kg; slot.minutes+=service;
    }
    const created=[];
    await pool.query("BEGIN");
    try{
      for(const slot of slots.filter(x=>x.orders.length)){
        const n="T-"+date.replace(/-/g,"")+"-"+(created.length+1);
        const first=slot.orders[0], last=slot.orders[slot.orders.length-1];
        const tr=(await q(`insert into trips(trip_number,customer_id,weight_kg,pieces,status,driver_id,vehicle_id,route,price_net,
          priority,planning_date,planned_sequence,assigned_vehicle_slot,planned_minutes,auto_planned,planned_start_at,dispatcher_note)
          values($1,$2,$3,$4,'Planned',$5,$6,$7,$8,$9,$10,$11,$12,$13,true,$14,$15) returning *`,
          [n,first.customer_id,slot.kg,slot.orders.reduce((a,x)=>a+Number(x.pieces||1),0),slot.driver.id,slot.vehicle.id,
           [first.pickup_address, ...slot.orders.map(x=>x.delivery_address)].filter(Boolean).join(" → "),
           slot.orders.reduce((a,x)=>a+Number(x.price_net||0),0),
           slot.orders.reduce((a,x)=>a+(x.priority==="urgent"?3:x.priority==="high"?2:1),0)>=3?"urgent":"normal",
           date,created.length+1,created.length+1,slot.minutes,
           (first.time_window_start||"")+(last.time_window_end?(" - "+last.time_window_end):""),
           "V48 automatisch aus offenen Aufträgen"]));
        let seq=1;
        for(const o of slot.orders){
          await q(`insert into trip_stops(trip_id,stop_order,address,customer_name,planned_time,planned_sequence,time_window_start,time_window_end,service_minutes)
            values($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
            [tr.id,seq++,o.delivery_address,o.customer_company||"",o.requested_date?o.requested_date:null,seq-1,o.time_window_start||null,o.time_window_end||null,Number(o.estimated_service_min||15)]);
          await q(`update orders set planned_trip_id=$1,planned_at=now(),status='planned' where id=$2`,[tr.id,o.id]);
        }
        created.push({trip:tr,order_count:slot.orders.length,kg:slot.kg,vehicle:slot.vehicle.name,driver:slot.driver.name});
      }
      await pool.query("COMMIT");
    }catch(e){await pool.query("ROLLBACK");throw e}
    await audit(req,"AUTO_DISPATCH_V48",`date=${date}; created=${created.length}; skipped=${skipped.length}`);
    res.json({date,created,skipped,remaining:orders.length-created.reduce((a,x)=>a+x.order_count,0)-skipped.length});
  }catch(e){res.status(400).json({error:e.message})}
});


// V49 dispatch board: load day, move/reorder orders and persist immediately
app.get("/api/dispatch/board",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const date=req.query.date || new Date().toISOString().slice(0,10);
    const trips=await q(`select t.*,u.name driver_name,v.name vehicle_name
      from trips t left join users u on u.id=t.driver_id left join vehicles v on v.id=t.vehicle_id
      where t.planning_date=$1 order by coalesce(t.dispatch_slot,t.assigned_vehicle_slot,1),coalesce(t.planned_sequence,999),t.created_at`,[date]);
    const orders=await q(`select o.*,c.company customer_company
      from orders o left join customers c on c.id=o.customer_id
      where (o.planned_trip_id is null or exists(select 1 from trips t where t.id=o.planned_trip_id and t.planning_date=$1))
      and coalesce(o.status,'new') in ('new','planned')
      order by case o.priority when 'urgent' then 0 when 'high' then 1 else 2 end,coalesce(o.dispatch_position,999),o.created_at`,[date]);
    const stops=await q(`select s.*,t.trip_number from trip_stops s join trips t on t.id=s.trip_id where t.planning_date=$1 order by t.id,s.stop_order`,[date]);
    res.json({date,trips,orders,stops})
  }catch(e){res.status(500).json({error:e.message})}
});
app.post("/api/dispatch/move-order",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  const {order_id,target_trip_id,position}=req.body;
  try{
    const o=(await q("select * from orders where id=$1",[order_id]))[0];
    if(!o)return res.status(404).json({error:"Auftrag nicht gefunden"});
    if(target_trip_id){
      const t=(await q("select * from trips where id=$1",[target_trip_id]))[0];
      if(!t)return res.status(404).json({error:"Tour nicht gefunden"});
      if(t.dispatch_locked)return res.status(409).json({error:"Tour ist gesperrt"});
      const current=Number((await q("select coalesce(sum(weight_kg),0) kg from orders where planned_trip_id=$1 and id<>$2",[target_trip_id,order_id]))[0].kg);
      if(current+Number(o.weight_kg||0)>1000)return res.status(400).json({error:"Tour würde 1000 KG überschreiten"});
      await q("update orders set planned_trip_id=$1,status='planned',dispatch_position=$2,planned_at=now() where id=$3",[target_trip_id,Number(position||999),order_id]);
      await q("update trip_stops set stop_order=stop_order+1 where trip_id=$1 and stop_order>=$2",[target_trip_id,Number(position||999)]);
      await q(`insert into trip_stops(trip_id,stop_order,address,customer_name,planned_sequence,time_window_start,time_window_end,service_minutes)
        values($1,$2,$3,$4,$2,$5,$6,$7)`,[target_trip_id,Number(position||999),o.delivery_address,o.customer_id?o.customer_reference||"":"",o.time_window_start||null,o.time_window_end||null,Number(o.estimated_service_min||15)]);
    }else{
      await q("update orders set planned_trip_id=null,status='new',dispatch_position=$1 where id=$2",[Number(position||999),order_id]);
    }
    await audit(req,"DISPATCH_MOVE",`${order_id} -> ${target_trip_id||"open"}`);
    res.json({ok:true})
  }catch(e){res.status(400).json({error:e.message})}
});
app.post("/api/dispatch/reorder",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  const {trip_id,order_ids=[]}=req.body;
  try{
    const t=(await q("select * from trips where id=$1",[trip_id]))[0];
    if(!t)return res.status(404).json({error:"Tour nicht gefunden"});
    if(t.dispatch_locked)return res.status(409).json({error:"Tour ist gesperrt"});
    for(let i=0;i<order_ids.length;i++) await q("update orders set dispatch_position=$1 where id=$2 and planned_trip_id=$3",[i+1,order_ids[i],trip_id]);
    const rows=await q("select o.*,c.company customer_company from orders o left join customers c on c.id=o.customer_id where o.planned_trip_id=$1 order by dispatch_position nulls last",[trip_id]);
    for(let i=0;i<rows.length;i++) await q("update trip_stops set stop_order=$1,planned_sequence=$1 where trip_id=$2 and address=$3",[i+1,trip_id,rows[i].delivery_address]);
    res.json({ok:true})
  }catch(e){res.status(400).json({error:e.message})}
});
app.post("/api/dispatch/lock-trip/:id",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{const r=await q("update trips set dispatch_locked=not dispatch_locked where id=$1 returning id,dispatch_locked",[req.params.id]);res.json(r[0])}
  catch(e){res.status(400).json({error:e.message})}
});


// V50 professional tour cards + stop-level ordering
app.get("/api/dispatch/tour-cards",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const date=req.query.date||new Date().toISOString().slice(0,10);
    const trips=await q(`select t.*,u.name driver_name,v.name vehicle_name,
      coalesce(sum(o.weight_kg),0) total_order_kg,coalesce(sum(o.price_net),0) total_revenue,
      count(o.id)::int order_count
      from trips t left join users u on u.id=t.driver_id left join vehicles v on v.id=t.vehicle_id
      left join orders o on o.planned_trip_id=t.id
      where t.planning_date=$1
      group by t.id,u.name,v.name order by coalesce(t.dispatch_slot,t.assigned_vehicle_slot,1),coalesce(t.planned_sequence,999)`,[date]);
    const stops=await q(`select s.*,o.reference order_reference,o.weight_kg order_weight,o.price_net order_price,
      c.company customer_company from trip_stops s
      left join orders o on o.planned_trip_id=s.trip_id and o.delivery_address=s.address
      left join customers c on c.id=o.customer_id
      join trips t on t.id=s.trip_id where t.planning_date=$1
      order by s.trip_id,coalesce(s.dispatch_position,s.stop_order),s.stop_order`,[date]);
    res.json({date,trips,stops})
  }catch(e){res.status(500).json({error:e.message})}
});
app.post("/api/dispatch/reorder-stops",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  const {trip_id,stop_ids=[]}=req.body;
  try{
    const t=(await q("select * from trips where id=$1",[trip_id]))[0];
    if(!t)return res.status(404).json({error:"Tour nicht gefunden"});
    if(t.dispatch_locked)return res.status(409).json({error:"Tour ist gesperrt"});
    for(let i=0;i<stop_ids.length;i++){
      await q("update trip_stops set dispatch_position=$1,stop_order=$1,planned_sequence=$1 where id=$2 and trip_id=$3",[i+1,stop_ids[i],trip_id]);
    }
    await audit(req,"STOP_REORDER",`${trip_id}: ${stop_ids.length} stops`);
    res.json({ok:true})
  }catch(e){res.status(400).json({error:e.message})}
});


// V51 route calculation for current stop order. Uses Google Routes API when configured, otherwise Haversine fallback.
function v51Geo(address){ return null; }
function v51Hav(a,b){
  if(!a||!b||a.lat==null||b.lat==null)return 0;
  const R=6371,la1=a.lat*Math.PI/180,la2=b.lat*Math.PI/180,dl=(b.lat-a.lat)*Math.PI/180,dg=(b.lng-a.lng)*Math.PI/180;
  const x=Math.sin(dl/2)**2+Math.cos(la1)*Math.cos(la2)*Math.sin(dg/2)**2;
  return R*2*Math.atan2(Math.sqrt(x),Math.sqrt(1-x));
}
async function v51GoogleRoute(points){
  const key=process.env.GOOGLE_ROUTES_API_KEY;if(!key||points.length<2)return null;
  const body={origin:{location:{latLng:{latitude:points[0].lat,longitude:points[0].lng}}},destination:{location:{latLng:{latitude:points[points.length-1].lat,longitude:points[points.length-1].lng}}},intermediates:points.slice(1,-1).map(p=>({location:{latLng:{latitude:p.lat,longitude:p.lng}}})),travelMode:"DRIVE",routingPreference:"TRAFFIC_AWARE",computeAlternativeRoutes:false};
  const rr=await fetch("https://routes.googleapis.com/directions/v2:computeRoutes",{method:"POST",headers:{"Content-Type":"application/json","X-Goog-Api-Key":key,"X-Goog-FieldMask":"routes.duration,routes.distanceMeters,routes.polyline.encodedPolyline"},body:JSON.stringify(body)});
  if(!rr.ok)return null; const d=await rr.json(); return d.routes?.[0]||null;
}
app.post("/api/planning/route/:tripId/calculate",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const trip=(await q("select * from trips where id=$1",[req.params.tripId]))[0];if(!trip)return res.status(404).json({error:"Tour nicht gefunden"});
    const stops=await q(`select * from trip_stops where trip_id=$1 order by coalesce(dispatch_position,stop_order),stop_order`,[trip.id]);
    const points=[trip.route_origin||null,...stops.map(x=>x.address),trip.route_destination||null].filter(Boolean);
    let totalKm=0,totalMin=0,source="heuristic";
    // If stored lat/lng are available, calculate segment estimates.
    const geo=stops.filter(x=>x.lat!=null&&x.lng!=null).map(x=>({lat:Number(x.lat),lng:Number(x.lng)}));
    if(geo.length>=2){
      for(let i=1;i<geo.length;i++){const km=v51Hav(geo[i-1],geo[i]);totalKm+=km;totalMin+=km/45*60}
    }
    let google=null;
    if(geo.length>=2) google=await v51GoogleRoute(geo);
    if(google){totalKm=Number(google.distanceMeters||0)/1000;totalMin=parseInt(String(google.duration||"0s").replace("s",""),10)/60;source="google_routes";}
    const start=trip.planned_start_at?new Date(trip.planned_start_at):new Date();
    let cursor=new Date(start.getTime());
    for(const st of stops){
      const service=Number(st.service_minutes||15);
      await q("update trip_stops set route_eta_at=$1,route_arrival_at=$1,route_departure_at=$2 where id=$3",[cursor,new Date(cursor.getTime()+service*60000),st.id]);
      cursor=new Date(cursor.getTime()+service*60000);
    }
    const end=new Date(start.getTime()+totalMin*60000+stops.reduce((a,x)=>a+Number(x.service_minutes||15),0)*60000);
    const r=await q(`update trips set route_total_distance_km=$1,route_total_duration_min=$2,route_eta_end_at=$3,route_calculated_at=now(),route_provider=$4,route_duration_min=$2,route_distance_km=$1 where id=$5
      returning *`,[Number(totalKm.toFixed(2)),Math.round(totalMin),end,source,trip.id]);
    await audit(req,"ROUTE_CALCULATED_V51",`${trip.trip_number}: ${totalKm.toFixed(2)} km / ${Math.round(totalMin)} min`);
    res.json({trip:r[0],stops,source,distance_km:Number(totalKm.toFixed(2)),duration_min:Math.round(totalMin),eta_end_at:end});
  }catch(e){res.status(400).json({error:e.message})}
});


// V52 geocoding: Google Geocoding API when configured, deterministic demo fallback otherwise.
async function v52Geocode(address){
  const key=process.env.GOOGLE_GEOCODING_API_KEY;
  if(key){
    const u="https://maps.googleapis.com/maps/api/geocode/json?address="+encodeURIComponent(address)+"&key="+encodeURIComponent(key);
    const rr=await fetch(u); if(rr.ok){const d=await rr.json();const loc=d.results?.[0]?.geometry?.location;if(loc)return {lat:loc.lat,lng:loc.lng,source:"google"};}
  }
  return null;
}
app.post("/api/geocode/customer/:id",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const c=(await q("select * from customers where id=$1",[req.params.id]))[0];if(!c)return res.status(404).json({error:"Kunde nicht gefunden"});
    const full=[c.address,c.city].filter(Boolean).join(", "); if(!full)return res.status(400).json({error:"Adresse fehlt"});
    const g=await v52Geocode(full); if(!g)return res.status(400).json({error:"Keine Geokodierung möglich; GOOGLE_GEOCODING_API_KEY konfigurieren"});
    const r=await q("update customers set lat=$1,lng=$2,geocoded_at=now() where id=$3 returning *",[g.lat,g.lng,c.id]);
    await audit(req,"CUSTOMER_GEOCODED",`${c.company}: ${g.lat},${g.lng}`);res.json(r[0]);
  }catch(e){res.status(400).json({error:e.message})}
});
app.post("/api/geocode/stop/:id",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const st=(await q("select * from trip_stops where id=$1",[req.params.id]))[0];if(!st)return res.status(404).json({error:"Stopp nicht gefunden"});
    const g=await v52Geocode(st.address);if(!g)return res.status(400).json({error:"Keine Geokodierung möglich; GOOGLE_GEOCODING_API_KEY konfigurieren"});
    const r=await q("update trip_stops set lat=$1,lng=$2,geocoded_at=now(),geocode_source=$3 where id=$4 returning *",[g.lat,g.lng,g.source,st.id]);
    res.json(r[0]);
  }catch(e){res.status(400).json({error:e.message})}
});
app.post("/api/geocode/trip/:id",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const stops=await q("select * from trip_stops where trip_id=$1 order by coalesce(dispatch_position,stop_order),stop_order",[req.params.id]);
    let done=0,failed=0;
    for(const st of stops){const g=await v52Geocode(st.address);if(g){await q("update trip_stops set lat=$1,lng=$2,geocoded_at=now(),geocode_source=$3 where id=$4",[g.lat,g.lng,g.source,st.id]);done++}else failed++}
    res.json({trip_id:req.params.id,geocoded:done,failed});
  }catch(e){res.status(400).json({error:e.message})}
});


// V53 map data for route visualization
app.get("/api/planning/route/:tripId/map-data",auth,roles("Admin","Dispatcher","Driver"),async(req,res)=>{
  try{
    const t=(await q(`select t.*,u.name driver_name,v.name vehicle_name from trips t
      left join users u on u.id=t.driver_id left join vehicles v on v.id=t.vehicle_id where t.id=$1`,[req.params.tripId]))[0];
    if(!t)return res.status(404).json({error:"Tour nicht gefunden"});
    const stops=await q(`select id,stop_order,dispatch_position,address,customer_name,lat,lng,route_eta_at,service_minutes,time_window_start,time_window_end
      from trip_stops where trip_id=$1 order by coalesce(dispatch_position,stop_order),stop_order`,[t.id]);
    const points=[];
    if(t.current_lat!=null&&t.current_lng!=null)points.push({type:"driver",lat:Number(t.current_lat),lng:Number(t.current_lng),label:"Fahrer"});
    for(const st of stops)if(st.lat!=null&&st.lng!=null)points.push({type:"stop",lat:Number(st.lat),lng:Number(st.lng),label:st.customer_name||st.address,stop_order:st.dispatch_position||st.stop_order,id:st.id,eta:st.route_eta_at});
    res.json({trip:t,stops,points,route:{distance_km:Number(t.route_total_distance_km||t.route_distance_km||0),duration_min:Number(t.route_total_duration_min||t.route_duration_min||0),eta_end_at:t.route_eta_end_at||t.eta_end_at||null,source:t.route_provider||"heuristic"}})
  }catch(e){res.status(500).json({error:e.message})}
});


// V54 Google Maps browser configuration
app.get("/api/config/maps",auth,roles("Admin","Dispatcher","Driver"),async(req,res)=>{
  res.json({browserKey:process.env.GOOGLE_MAPS_BROWSER_KEY||"",enabled:!!process.env.GOOGLE_MAPS_BROWSER_KEY});
});


// V55 live driver tracking snapshot
app.get("/api/control-center/trip/:id/live",auth,roles("Admin","Dispatcher","Driver"),async(req,res)=>{
  try{
    const t=(await q(`select t.*,u.name driver_name,v.name vehicle_name from trips t
      left join users u on u.id=t.driver_id left join vehicles v on v.id=t.vehicle_id where t.id=$1`,[req.params.id]))[0];
    if(!t)return res.status(404).json({error:"Tour nicht gefunden"});
    const stop=(await q(`select * from trip_stops where trip_id=$1 and delivered_at is null order by coalesce(dispatch_position,stop_order),stop_order limit 1`,[t.id]))[0]||null;
    const gpsAt=t.gps_last_at||t.last_driver_ping_at||null;
    const age=gpsAt?Math.max(0,Math.round((Date.now()-new Date(gpsAt).getTime())/1000)):null;
    const status=age==null||age>180?"offline":age>60?"stale":"online";
    await q("update trips set gps_status=$1,gps_last_at=coalesce(gps_last_at,last_driver_ping_at) where id=$2",[status,t.id]);
    res.json({trip:t,driver:{id:t.driver_id,name:t.driver_name},vehicle:{id:t.vehicle_id,name:t.vehicle_name},gps:{lat:t.current_lat,lng:t.current_lng,accuracy:t.gps_last_accuracy,at:gpsAt,age_seconds:age,status},active_stop:stop,eta:{at:t.eta_at||t.route_eta_end_at||null,minutes:t.eta_minutes||t.last_eta_minutes||null}})
  }catch(e){res.status(500).json({error:e.message})}
});
app.post("/api/control-center/trip/:id/heartbeat",auth,roles("Driver","Admin","Dispatcher"),async(req,res)=>{
  try{
    const lat=req.body.lat!=null?Number(req.body.lat):null,lng=req.body.lng!=null?Number(req.body.lng):null,acc=req.body.accuracy!=null?Number(req.body.accuracy):null;
    const r=await q(`update trips set current_lat=coalesce($1,current_lat),current_lng=coalesce($2,current_lng),
      gps_last_accuracy=coalesce($3,gps_last_accuracy),gps_last_at=now(),last_driver_ping_at=now(),gps_status='online' where id=$4 returning *`,[lat,lng,acc,req.params.id]);
    if(!r.length)return res.status(404).json({error:"Tour nicht gefunden"});res.json({ok:true,trip:r[0]})
  }catch(e){res.status(400).json({error:e.message})}
});


// V56 driver GPS session endpoint
app.post("/api/driver/live-gps",auth,roles("Driver","Admin"),async(req,res)=>{
  try{
    const tripId=req.body.trip_id;
    const driverId=req.user.role==="Driver"?req.user.id:req.body.driver_id;
    if(!tripId)return res.status(400).json({error:"trip_id erforderlich"});
    const t=(await q("select * from trips where id=$1",[tripId]))[0];
    if(!t)return res.status(404).json({error:"Tour nicht gefunden"});
    if(req.user.role==="Driver" && t.driver_id!==req.user.id)return res.status(403).json({error:"Tour nicht dem Fahrer zugewiesen"});
    const lat=Number(req.body.lat),lng=Number(req.body.lng),accuracy=req.body.accuracy==null?null:Number(req.body.accuracy);
    if(!Number.isFinite(lat)||!Number.isFinite(lng))return res.status(400).json({error:"Ungültige GPS-Koordinaten"});
    await q(`insert into gps_points(trip_id,driver_id,lat,lng,accuracy) values($1,$2,$3,$4,$5)`,[tripId,driverId,lat,lng,accuracy]);
    const r=await q(`update trips set current_lat=$1,current_lng=$2,gps_last_accuracy=$3,gps_last_at=now(),last_driver_ping_at=now(),gps_status='online' where id=$4 returning id,current_lat,current_lng,gps_last_at,gps_status`,[lat,lng,accuracy,tripId]);
    res.json({ok:true,trip:r[0]})
  }catch(e){res.status(400).json({error:e.message})}
});
app.get("/api/driver/live-session",auth,roles("Driver","Admin"),async(req,res)=>{
  try{
    const driverId=req.user.role==="Driver"?req.user.id:req.query.driver_id;
    const t=(await q(`select t.*,v.name vehicle_name from trips t left join vehicles v on v.id=t.vehicle_id
      where t.driver_id=$1 and t.status in ('Planned','In Transit') order by t.planned_start_at nulls last limit 1`,[driverId]))[0]||null;
    res.json({active:t})
  }catch(e){res.status(500).json({error:e.message})}
});


// V57 unified live tracking + ETA refresh + GPS alert state
app.get("/api/control-center/trip/:id/live-full",auth,roles("Admin","Dispatcher","Driver"),async(req,res)=>{
  try{
    const t=(await q(`select t.*,u.name driver_name,v.name vehicle_name from trips t left join users u on u.id=t.driver_id left join vehicles v on v.id=t.vehicle_id where t.id=$1`,[req.params.id]))[0];
    if(!t)return res.status(404).json({error:"Tour nicht gefunden"});
    const stops=await q(`select * from trip_stops where trip_id=$1 order by coalesce(dispatch_position,stop_order),stop_order`,[t.id]);
    const active=stops.find(x=>!x.delivered_at)||null;
    const gpsAt=t.gps_last_at||t.last_driver_ping_at||null;
    const age=gpsAt?Math.max(0,Math.round((Date.now()-new Date(gpsAt).getTime())/1000)):null;
    const gpsStatus=age==null||age>180?"offline":age>60?"stale":"online";
    let etaMin=null;
    if(active&&t.current_lat!=null&&t.current_lng!=null&&active.lat!=null&&active.lng!=null){
      const R=6371,la1=Number(t.current_lat)*Math.PI/180,la2=Number(active.lat)*Math.PI/180,dl=(Number(active.lat)-Number(t.current_lat))*Math.PI/180,dg=(Number(active.lng)-Number(t.current_lng))*Math.PI/180;
      const x=Math.sin(dl/2)**2+Math.cos(la1)*Math.cos(la2)*Math.sin(dg/2)**2,km=R*2*Math.atan2(Math.sqrt(x),Math.sqrt(1-x));etaMin=Math.max(1,Math.round(km/45*60));
      await q("update trips set eta_minutes=$1,eta_at=now()+($1||' minutes')::interval,last_eta_at=now() where id=$2",[etaMin,t.id]);
    }
    let alert=null;
    if(gpsStatus==="offline"||gpsStatus==="stale"){
      alert={type:"gps",severity:gpsStatus==="offline"?"critical":"warning",message:`GPS ${gpsStatus==="offline"?"ausgefallen":"veraltet"}: ${age==null?"keine Position":age+" Sekunden alt"}`};
      await q("update trips set live_alert_state=$1 where id=$2",[alert.severity,t.id]);
    }else await q("update trips set live_alert_state='normal' where id=$1",[t.id]);
    res.json({trip:t,gps:{lat:t.current_lat,lng:t.current_lng,accuracy:t.gps_last_accuracy,at:gpsAt,age_seconds:age,status:gpsStatus},active_stop:active,stops,eta:{minutes:etaMin||t.eta_minutes||null,at:t.eta_at||null},alert});
  }catch(e){res.status(500).json({error:e.message})}
});


// V58 live alert engine: GPS, ETA, geofence and stop movement
function v58DistKm(lat1,lng1,lat2,lng2){
  const R=6371,la1=Number(lat1)*Math.PI/180,la2=Number(lat2)*Math.PI/180,dl=(Number(lat2)-Number(lat1))*Math.PI/180,dg=(Number(lng2)-Number(lng1))*Math.PI/180;
  const x=Math.sin(dl/2)**2+Math.cos(la1)*Math.cos(la2)*Math.sin(dg/2)**2;return R*2*Math.atan2(Math.sqrt(x),Math.sqrt(1-x));
}
app.post("/api/control-center/alerts/check-live",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const trips=await q(`select * from trips where status in ('Planned','In Transit') and driver_id is not null`);
    let created=0,states=[];
    for(const t of trips){
      const gpsAt=t.gps_last_at||t.last_driver_ping_at;
      const age=gpsAt?Math.max(0,Math.round((Date.now()-new Date(gpsAt).getTime())/1000)):null;
      const active=(await q(`select * from trip_stops where trip_id=$1 and delivered_at is null order by coalesce(dispatch_position,stop_order),stop_order limit 1`,[t.id]))[0];
      const alerts=[];
      if(age==null||age>180)alerts.push(["gps_offline","critical",`GPS seit ${age==null?"unbekannt":age+" Sekunden"} nicht aktualisiert`]);
      else if(age>60)alerts.push(["gps_stale","warning",`GPS ist ${age} Sekunden alt`]);
      if(active&&t.current_lat!=null&&t.current_lng!=null&&active.lat!=null&&active.lng!=null){
        const km=v58DistKm(t.current_lat,t.current_lng,active.lat,active.lng);
        const radius=Number(t.arrival_radius_m||150)/1000;
        if(km<=radius)alerts.push(["geofence_arrived","info",`Fahrzeug innerhalb des Geofence für ${active.address}`]);
        const eta=Number(t.eta_minutes||t.last_eta_minutes||0);
        if(eta>0&&t.eta_at&&new Date(t.eta_at)<new Date(Date.now()-10*60000))alerts.push(["eta_exceeded","warning",`ETA für ${active.address} überschritten`]);
      }
      for(const [type,severity,message] of alerts){
        const recent=await q(`select id from control_alerts where trip_id=$1 and type=$2 and created_at>now()-interval '10 minutes' and acknowledged=false limit 1`,[t.id,type]);
        if(!recent.length){await q(`insert into control_alerts(trip_id,type,severity,message) values($1,$2,$3,$4)`,[t.id,type,severity,message]);created++}
      }
      states.push({trip_id:t.id,alert_count:alerts.length});
    }
    res.json({created,states})
  }catch(e){res.status(500).json({error:e.message})}
});
app.get("/api/control-center/alerts/live",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const r=await q(`select a.*,t.trip_number,u.name driver_name,v.name vehicle_name from control_alerts a
      left join trips t on t.id=a.trip_id left join users u on u.id=t.driver_id left join vehicles v on v.id=t.vehicle_id
      where a.acknowledged=false order by case a.severity when 'critical' then 0 when 'warning' then 1 else 2 end,a.created_at desc`);
    res.json(r)
  }catch(e){res.status(500).json({error:e.message})}
});


// V59 automatic geofence arrival and next-stop activation
app.post("/api/driver/stops/:id/geofence-check",auth,roles("Driver","Admin"),async(req,res)=>{
  try{
    const st=(await q(`select s.*,t.driver_id,t.arrival_radius_m,t.current_lat,t.current_lng,t.trip_number
      from trip_stops s join trips t on t.id=s.trip_id where s.id=$1`,[req.params.id]))[0];
    if(!st)return res.status(404).json({error:"Stopp nicht gefunden"});
    if(req.user.role==="Driver" && st.driver_id!==req.user.id)return res.status(403).json({error:"Nicht deine Tour"});
    const lat=Number(req.body.lat),lng=Number(req.body.lng);
    if(!Number.isFinite(lat)||!Number.isFinite(lng)||st.lat==null||st.lng==null)return res.status(400).json({error:"GPS oder Stoppkoordinaten fehlen"});
    const R=6371,la1=lat*Math.PI/180,la2=Number(st.lat)*Math.PI/180,dl=(Number(st.lat)-lat)*Math.PI/180,dg=(Number(st.lng)-lng)*Math.PI/180;
    const x=Math.sin(dl/2)**2+Math.cos(la1)*Math.cos(la2)*Math.sin(dg/2)**2,km=R*2*Math.atan2(Math.sqrt(x),Math.sqrt(1-x)),meters=km*1000;
    const arrived=meters<=Number(st.arrival_radius_m||150);
    if(arrived && !st.geofence_arrived_at){
      await q(`update trip_stops set geofence_arrived_at=now(),arrived_at=coalesce(arrived_at,now()),status=coalesce(status,'Arrived') where id=$1`,[st.id]);
      await q(`insert into control_alerts(trip_id,type,severity,message) values($1,'geofence_arrived','info',$2)`,[st.trip_id,`Fahrer ist bei Stopp ${st.stop_order}: ${st.address}`]);
      await q(`update trips set current_lat=$1,current_lng=$2,gps_last_at=now(),gps_status='online' where id=$3`,[lat,lng,st.trip_id]);
    }
    const next=(await q(`select * from trip_stops where trip_id=$1 and delivered_at is null and id<>$2 order by coalesce(dispatch_position,stop_order),stop_order limit 1`,[st.trip_id,st.id]))[0]||null;
    res.json({arrived,distance_m:Math.round(meters),stop:st,next_stop:next})
  }catch(e){res.status(400).json({error:e.message})}
});
app.post("/api/driver/stops/:id/activate-next",auth,roles("Driver","Admin"),async(req,res)=>{
  try{
    const st=(await q("select * from trip_stops where id=$1",[req.params.id]))[0];if(!st)return res.status(404).json({error:"Stopp nicht gefunden"});
    const next=(await q(`select * from trip_stops where trip_id=$1 and delivered_at is null order by coalesce(dispatch_position,stop_order),stop_order limit 1`,[st.trip_id]))[0]||null;
    if(!next)return res.json({completed:true});
    await q(`update trips set eta_at=$1,eta_minutes=$2,last_eta_at=now() where id=$3`,[next.route_eta_at||null,next.eta_minutes||null,st.trip_id]);
    res.json({completed:false,next_stop:next})
  }catch(e){res.status(400).json({error:e.message})}
});


// V60 unified driver delivery workflow
app.get("/api/driver/workflow/:tripId",auth,roles("Driver","Admin"),async(req,res)=>{
  try{
    const t=(await q(`select t.*,u.name driver_name,v.name vehicle_name from trips t left join users u on u.id=t.driver_id left join vehicles v on v.id=t.vehicle_id where t.id=$1`,[req.params.tripId]))[0];
    if(!t)return res.status(404).json({error:"Tour nicht gefunden"});
    if(req.user.role==="Driver"&&t.driver_id!==req.user.id)return res.status(403).json({error:"Nicht deine Tour"});
    const stops=await q(`select * from trip_stops where trip_id=$1 order by coalesce(dispatch_position,stop_order),stop_order`,[t.id]);
    res.json({trip:t,stops,active:stops.find(x=>!x.delivered_at)||null})
  }catch(e){res.status(500).json({error:e.message})}
});
app.post("/api/driver/workflow/:tripId/complete-stop",auth,roles("Driver","Admin"),async(req,res)=>{
  try{
    const t=(await q("select * from trips where id=$1",[req.params.tripId]))[0];if(!t)return res.status(404).json({error:"Tour nicht gefunden"});
    if(req.user.role==="Driver"&&t.driver_id!==req.user.id)return res.status(403).json({error:"Nicht deine Tour"});
    const st=(await q("select * from trip_stops where id=$1 and trip_id=$2",[req.body.stop_id,t.id]))[0];if(!st)return res.status(404).json({error:"Stopp nicht gefunden"});
    if(!req.body.signature_data&&!req.body.delivery_photo)return res.status(400).json({error:"Foto oder Unterschrift erforderlich"});
    const kg=Number(req.body.delivered_kg||st.delivered_kg||0),pieces=Math.max(1,parseInt(req.body.delivered_pieces||st.delivered_pieces||1,10));
    await q(`update trip_stops set delivered_kg=$1,delivered_pieces=$2,delivery_note=$3,delivery_photo=$4,signature_data=$5,
      proof_at=now(),proof_device=$6,delivered_at=now(),status='Delivered' where id=$7`,
      [kg,pieces,req.body.delivery_note||"",req.body.delivery_photo||st.delivery_photo||null,req.body.signature_data||st.signature_data||null,req.body.device||"driver-web",st.id]);
    const left=(await q("select count(*) n from trip_stops where trip_id=$1 and delivered_at is null",[t.id]))[0].n;
    if(Number(left)===0){
      await q("update trips set status='Delivered',actual_finished_at=now(),live_status='completed' where id=$1",[t.id]);
      await audit(req,"TRIP_COMPLETED",t.trip_number);
    }
    res.json({ok:true,remaining:Number(left),trip_completed:Number(left)===0})
  }catch(e){res.status(400).json({error:e.message})}
});


// V61 automatic DDT + invoice finalization after completed trip
app.post("/api/trips/:id/finalize-documents",auth,roles("Admin","Dispatcher","Accounting"),async(req,res)=>{
  try{
    const trip=(await q(`select t.*,c.company customer_company,c.id cid from trips t left join customers c on c.id=t.customer_id where t.id=$1`,[req.params.id]))[0];
    if(!trip)return res.status(404).json({error:"Tour nicht gefunden"});
    const open=(await q("select count(*) n from trip_stops where trip_id=$1 and delivered_at is null",[trip.id]))[0].n;
    if(Number(open)>0)return res.status(400).json({error:"Nicht alle Stopps sind geliefert"});
    let ddt=(await q("select * from delivery_documents where trip_id=$1",[trip.id]))[0]||null;
    if(!ddt){
      const num="DDT-"+Date.now().toString().slice(-8);
      ddt=(await q(`insert into delivery_documents(trip_id,document_number,issued_at,status,proof_complete) values($1,$2,now(),'Completed',true) returning *`,[trip.id,num]))[0];
    }
    let inv=(await q("select * from invoices where trip_id=$1",[trip.id]))[0]||null;
    if(!inv && Number(trip.price_net||0)>0){
      const net=Number(trip.price_net),vatRate=Number(req.body.vat_rate||22),vat=Number((net*vatRate/100).toFixed(2)),gross=Number((net+vat).toFixed(2));
      const due=new Date(Date.now()+30*86400000).toISOString().slice(0,10);
      const num="INV-"+Date.now().toString().slice(-8);
      inv=(await q(`insert into invoices(invoice_number,customer_id,trip_id,issue_date,due_date,net,vat_rate,vat,gross,status,description,currency,payment_terms_days)
        values($1,$2,$3,current_date,$4,$5,$6,$7,$8,'Open',$9,'EUR',30) returning *`,
        [num,trip.cid,trip.id,due,net,vatRate,vat,gross,`Transporttour ${trip.trip_number}`]))[0];
    }
    await audit(req,"DOCUMENTS_FINALIZED",`${trip.trip_number}: DDT=${ddt.document_number}; invoice=${inv?.invoice_number||"none"}`);
    res.json({ok:true,trip,ddt,invoice:inv})
  }catch(e){res.status(400).json({error:e.message})}
});


// V62 document center
app.get("/api/documents/center",auth,roles("Admin","Dispatcher","Accounting"),async(req,res)=>{
  try{
    const invoices=await q(`select i.*,c.company customer_company,t.trip_number from invoices i left join customers c on c.id=i.customer_id left join trips t on t.id=i.trip_id order by i.issue_date desc,i.created_at desc limit 300`);
    const ddts=await q(`select d.*,t.trip_number,c.company customer_company from delivery_documents d join trips t on t.id=d.trip_id left join customers c on c.id=t.customer_id order by d.issued_at desc limit 300`);
    const summary=(await q(`select count(*)::int invoice_count,coalesce(sum(case when status='Open' then gross else 0 end),0) open_gross,
      coalesce(sum(case when status='Overdue' then gross else 0 end),0) overdue_gross,
      coalesce(sum(case when status='Paid' then gross else 0 end),0) paid_gross from invoices`))[0];
    res.json({invoices,ddts,summary})
  }catch(e){res.status(500).json({error:e.message})}
});
app.post("/api/documents/refresh-status",auth,roles("Admin","Accounting"),async(req,res)=>{
  try{
    const r=await q(`update invoices set status='Overdue' where status='Open' and due_date<current_date returning id`);
    res.json({updated:r.length})
  }catch(e){res.status(400).json({error:e.message})}
});


// V63 document send center
app.post("/api/documents/send",auth,roles("Admin","Dispatcher","Accounting"),async(req,res)=>{
  try{
    const invoiceId=req.body.invoice_id||null, ddtId=req.body.delivery_document_id||null;
    if(!invoiceId&&!ddtId)return res.status(400).json({error:"invoice_id oder delivery_document_id erforderlich"});
    let customerId=null,recipient=req.body.recipient||"";
    if(invoiceId){
      const i=(await q(`select i.*,c.email,c.company from invoices i left join customers c on c.id=i.customer_id where i.id=$1`,[invoiceId]))[0];
      if(!i)return res.status(404).json({error:"Rechnung nicht gefunden"});customerId=i.customer_id;recipient=recipient||i.email||"";
    }else{
      const d=(await q(`select d.*,t.customer_id,c.email,c.company from delivery_documents d join trips t on t.id=d.trip_id left join customers c on c.id=t.customer_id where d.id=$1`,[ddtId]))[0];
      if(!d)return res.status(404).json({error:"DDT nicht gefunden"});customerId=d.customer_id;recipient=recipient||d.email||"";
    }
    if(!recipient)return res.status(400).json({error:"Empfänger-E-Mail fehlt"});
    const subject=req.body.subject||`Emergency Delivery Dokument${invoiceId?" – Rechnung":" – DDT"}`;
    const body=req.body.body_html||`Guten Tag,<br><br>anbei erhalten Sie Ihr Dokument von Emergency Delivery.<br><br>Mit freundlichen Grüßen`;
    const r=await q(`insert into email_outbox(customer_id,invoice_id,delivery_document_id,recipient,subject,body_html,status) values($1,$2,$3,$4,$5,$6,'Queued') returning *`,
      [customerId,invoiceId,ddtId,recipient,subject,body]);
    await audit(req,"DOCUMENT_EMAIL_QUEUED",`${invoiceId||ddtId} -> ${recipient}`);
    res.json(r[0])
  }catch(e){res.status(400).json({error:e.message})}
});
app.get("/api/documents/send-status",auth,roles("Admin","Dispatcher","Accounting"),async(req,res)=>{
  try{
    const r=await q(`select e.*,c.company customer_company from email_outbox e left join customers c on c.id=e.customer_id order by e.queued_at desc limit 200`);
    res.json(r)
  }catch(e){res.status(500).json({error:e.message})}
});


// V64 customer 360
app.get("/api/customers/:id/360",auth,roles("Admin","Dispatcher","Accounting"),async(req,res)=>{
  try{
    const id=req.params.id;
    const customer=(await q(`select * from customers where id=$1`,[id]))[0];
    if(!customer)return res.status(404).json({error:"Kunde nicht gefunden"});
    const orders=await q(`select o.*,t.trip_number,t.status trip_status from orders o left join trips t on t.id=o.planned_trip_id where o.customer_id=$1 order by o.created_at desc limit 100`,[id]);
    const invoices=await q(`select i.*,t.trip_number from invoices i left join trips t on t.id=i.trip_id where i.customer_id=$1 order by i.issue_date desc limit 100`,[id]);
    const ddts=await q(`select d.*,t.trip_number from delivery_documents d join trips t on t.id=d.trip_id where t.customer_id=$1 order by d.issued_at desc limit 100`,[id]);
    const emails=await q(`select * from email_outbox where customer_id=$1 order by queued_at desc limit 100`,[id]);
    const totals=(await q(`select coalesce(sum(gross),0) total_billed,coalesce(sum(case when status in('Open','Overdue') then gross else 0 end),0) outstanding from invoices where customer_id=$1`,[id]))[0];
    res.json({customer,orders,invoices,ddts,emails,totals})
  }catch(e){res.status(500).json({error:e.message})}
});


// V65 customer management
app.delete("/api/customers/manage/:id",auth,roles("Admin","Dispatcher","Accounting"),async(req,res)=>{
  try{
    const used=await q("select count(*)::int n from trips where customer_id=$1",[req.params.id]);
    const orders=await q("select count(*)::int n from orders where customer_id=$1",[req.params.id]);
    const invoices=await q("select count(*)::int n from invoices where customer_id=$1",[req.params.id]);
    if(Number(used[0]?.n||0)+Number(orders[0]?.n||0)+Number(invoices[0]?.n||0)>0)
      return res.status(409).json({error:"Kunde kann nicht gelöscht werden, weil bereits Aufträge, Touren oder Rechnungen vorhanden sind. Bitte zuerst archivieren."});
    const r=await q("delete from customers where id=$1 returning id,company",[req.params.id]);
    if(!r.length)return res.status(404).json({error:"Kunde nicht gefunden"});
    await audit(req,"CUSTOMER_DELETED",r[0].company);res.json({ok:true});
  }catch(e){res.status(500).json({error:e.message})}
});
app.get("/api/customers/manage",auth,roles("Admin","Dispatcher","Accounting"),async(req,res)=>{
  try{
    const rows=await q(`select c.*,coalesce(sum(i.gross) filter(where i.status in('Open','Overdue')),0) outstanding,
      count(distinct o.id)::int order_count
      from customers c left join invoices i on i.customer_id=c.id left join orders o on o.customer_id=c.id
      group by c.id order by c.company`);
    res.json(rows)
  }catch(e){res.status(500).json({error:e.message})}
});
app.post("/api/customers/manage",auth,roles("Admin","Dispatcher","Accounting"),async(req,res)=>{
  try{
    const b=req.body||{};
    if(!b.company)return res.status(400).json({error:"Firma erforderlich"});
    const r=await q(`insert into customers(company,vat_id,address,city,email,phone,lat,lng) values($1,$2,$3,$4,$5,$6,$7,$8) returning *`,
      [b.company,b.vat_id||null,b.address||null,b.city||null,b.email||null,b.phone||null,b.lat||null,b.lng||null]);
    await audit(req,"CUSTOMER_CREATED",r[0].company);
    res.json(r[0])
  }catch(e){res.status(400).json({error:e.message})}
});
app.patch("/api/customers/manage/:id",auth,roles("Admin","Dispatcher","Accounting"),async(req,res)=>{
  try{
    const b=req.body||{}, id=req.params.id;
    const r=await q(`update customers set company=coalesce($1,company),vat_id=coalesce($2,vat_id),address=coalesce($3,address),
      city=coalesce($4,city),email=coalesce($5,email),phone=coalesce($6,phone),lat=coalesce($7,lat),lng=coalesce($8,lng)
      where id=$9 returning *`,[b.company,b.vat_id,b.address,b.city,b.email,b.phone,b.lat,b.lng,id]);
    if(!r.length)return res.status(404).json({error:"Kunde nicht gefunden"});
    await audit(req,"CUSTOMER_UPDATED",r[0].company);
    res.json(r[0])
  }catch(e){res.status(400).json({error:e.message})}
});


// V66 connected order entry
app.get("/api/order-entry/customers",auth,roles("Admin","Dispatcher","Accounting"),async(req,res)=>{
  try{
    const r=await q(`select id,company,vat_id,address,city,email,phone from customers order by company`);
    res.json(r)
  }catch(e){res.status(500).json({error:e.message})}
});
app.post("/api/order-entry/create",auth,roles("Admin","Dispatcher","Accounting"),async(req,res)=>{
  try{
    const b=req.body||{};
    if(!b.customer_id)return res.status(400).json({error:"Kunde erforderlich"});
    if(!b.delivery_address)return res.status(400).json({error:"Lieferadresse erforderlich"});
    const kg=Number(b.weight_kg||0), pieces=Math.max(1,Number(b.pieces||1));
    if(!Number.isFinite(kg)||kg<0||kg>1000)return res.status(400).json({error:"Gewicht muss zwischen 0 und 1000 KG liegen"});
    let price=Number(b.price_net);
    if(!Number.isFinite(price)){
      try{
        const calc=await q(`select * from customer_price_rules where customer_id=$1 and active=true and $2 between min_weight_kg and max_weight_kg order by min_weight_kg desc limit 1`,
          [b.customer_id,kg]);
        const r=calc[0];
        if(r) price=Math.max(Number(r.minimum_price||0),Number(r.base_price||0)+kg*Number(r.price_per_kg||0)+(b.priority==="urgent"?Number(r.urgent_surcharge||0):0));
        else price=0;
      }catch(_){price=0}
    }
    const r=await q(`insert into orders(customer_id,pickup_address,pickup_city,delivery_address,delivery_city,weight_kg,pieces,customer_reference,price_net,status,priority,requested_date,time_window_start,time_window_end,estimated_service_min)
      values($1,$2,$3,$4,$5,$6,$7,$8,$9,'new',$10,$11,$12,$13,$14) returning *`,
      [b.customer_id,b.pickup_address||null,b.pickup_city||null,b.delivery_address,b.delivery_city||null,kg,pieces,b.customer_reference||null,price,
       b.priority||"normal",b.requested_date||null,b.time_window_start||null,b.time_window_end||null,Math.max(0,Number(b.estimated_service_min||15))]);
    await audit(req,"ORDER_CREATED",`order=${r[0].id};customer=${b.customer_id}`);
    res.json({order:r[0],calculated_price:price})
  }catch(e){res.status(400).json({error:e.message})}
});


// V67 end-to-end order dispatch
app.post("/api/flow/dispatch-order/:id",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const id=req.params.id;
    const o=(await q(`select o.*,c.company,c.address customer_address,c.city customer_city from orders o join customers c on c.id=o.customer_id where o.id=$1`,[id]))[0];
    if(!o)return res.status(404).json({error:"Auftrag nicht gefunden"});
    if(o.planned_trip_id)return res.json({message:"Auftrag bereits disponiert",trip_id:o.planned_trip_id});
    const date=o.requested_date||new Date().toISOString().slice(0,10);
    const trips=await q(`select t.*,v.name vehicle_name,v.plate,d.name driver_name,
      coalesce(sum(s.weight_kg),0) stop_kg from trips t
      left join vehicles v on v.id=t.vehicle_id left join users d on d.id=t.driver_id
      left join trip_stops s on s.trip_id=t.id
      where t.planning_date=$1 and t.dispatch_locked=false and t.status not in('Delivered','Cancelled')
      group by t.id,v.name,v.plate,d.name order by t.dispatch_slot nulls last,t.created_at`,[date]);
    let chosen=trips.find(t=>Number(t.stop_kg||0)+Number(o.weight_kg||0)<=1000);
    if(!chosen){
      const vehicles=await q(`select id,name,plate from vehicles where active=true order by name`);
      const drivers=await q(`select id,name from users where role='Driver' and active=true order by name`);
      if(!vehicles.length||!drivers.length)return res.status(400).json({error:"Kein aktives Fahrzeug oder Fahrer verfügbar"});
      const slot=(await q(`select coalesce(max(dispatch_slot),0)+1 n from trips where planning_date=$1`,[date]))[0].n;
      chosen=(await q(`insert into trips(trip_number,planning_date,dispatch_slot,assigned_vehicle_slot,driver_id,vehicle_id,customer_id,weight_kg,status,priority,price_net,auto_planned)
        values('T-'+to_char(now(),'YYYYMMDDHH24MISSMS'),$1,$2,$2,$3,$4,$5,$6,'Planned',$7,$8,true) returning *`,
        [date,slot,drivers[0].id,vehicles[Math.min(slot-1,vehicles.length-1)].id,o.customer_id,o.weight_kg||0,o.priority||"normal",o.price_net||0])).then(x=>x[0]);
    }else{
      await q(`update trips set weight_kg=weight_kg+$1,price_net=price_net+$2,customer_id=coalesce(customer_id,$3),priority=case when $4='urgent' then 'urgent' else priority end where id=$5`,
        [o.weight_kg||0,o.price_net||0,o.customer_id,o.priority||"normal",chosen.id]);
      chosen=(await q(`select * from trips where id=$1`,[chosen.id]))[0];
    }
    const pos=(await q(`select coalesce(max(dispatch_position),0)+1 n from trip_stops where trip_id=$1`,[chosen.id]))[0].n;
    await q(`insert into trip_stops(trip_id,stop_order,dispatch_position,address,customer_name,planned_window_start,planned_window_end,service_minutes) values($1,$2,$2,$3,$4,$5,$6,$7)`,
      [chosen.id,pos,o.delivery_address,o.company,o.time_window_start||null,o.time_window_end||null,o.estimated_service_min||15]);
    await q(`update orders set status='planned',planned_trip_id=$1,planned_at=now() where id=$2`,[chosen.id,id]);
    await audit(req,"ORDER_DISPATCHED",`order=${id};trip=${chosen.id}`);
    res.json({ok:true,trip_id:chosen.id})
  }catch(e){res.status(400).json({error:e.message})}
});
app.get("/api/flow/overview",auth,roles("Admin","Dispatcher","Accounting"),async(req,res)=>{
  try{
    const open=await q(`select o.id,o.customer_reference,o.weight_kg,o.priority,o.requested_date,o.delivery_address,o.status,c.company from orders o join customers c on c.id=o.customer_id where o.status='new' order by o.requested_date nulls last,o.created_at desc limit 100`);
    const trips=await q(`select t.id,t.trip_number,t.status,t.planning_date,t.weight_kg,t.price_net,t.dispatch_slot,v.name vehicle_name,v.plate,u.name driver_name,count(s.id)::int stop_count
      from trips t left join vehicles v on v.id=t.vehicle_id left join users u on u.id=t.driver_id left join trip_stops s on s.trip_id=t.id
      where t.status<>'Delivered' group by t.id,v.name,v.plate,u.name order by t.planning_date desc nulls last,t.dispatch_slot`);
    res.json({open,trips})
  }catch(e){res.status(500).json({error:e.message})}
});


// V68 professional dispatch board
app.get("/api/dispatch/pro-board",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const date=req.query.date||new Date().toISOString().slice(0,10);
    const rows=await q(`select t.*,v.name vehicle_name,v.plate,u.name driver_name,
      coalesce(sum(s.weight_kg),0) stop_kg,coalesce(sum(s.planned_revenue_net),0) stop_revenue,count(s.id)::int stop_count
      from trips t left join vehicles v on v.id=t.vehicle_id left join users u on u.id=t.driver_id
      left join trip_stops s on s.trip_id=t.id
      where t.planning_date=$1 and t.status<>'Delivered'
      group by t.id,v.name,v.plate,u.name order by coalesce(t.dispatch_slot,99),t.created_at`,[date]);
    const orders=await q(`select o.id,o.customer_reference,o.weight_kg,o.priority,o.delivery_address,o.status,c.company,o.planned_trip_id
      from orders o join customers c on c.id=o.customer_id where o.status='new' order by o.priority desc,o.created_at`);
    const drivers=await q(`select id,name from users where role='Driver' and active=true order by name`);
    const vehicles=await q(`select id,name,plate from vehicles where active=true order by name`);
    const stops=await q(`select s.*,t.trip_number from trip_stops s join trips t on t.id=s.trip_id where t.planning_date=$1 order by s.trip_id,s.dispatch_position nulls last,s.stop_order`,[date]);
    res.json({date,trips:rows,orders,drivers,vehicles,stops})
  }catch(e){res.status(500).json({error:e.message})}
});
app.post("/api/dispatch/pro-assign",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const {trip_id,driver_id,vehicle_id}=req.body||{};
    if(!trip_id)return res.status(400).json({error:"trip_id erforderlich"});
    const r=await q(`update trips set driver_id=coalesce($1,driver_id),vehicle_id=coalesce($2,vehicle_id) where id=$3 returning *`,[driver_id||null,vehicle_id||null,trip_id]);
    if(!r.length)return res.status(404).json({error:"Tour nicht gefunden"});
    await audit(req,"DISPATCH_ASSIGN",`trip=${trip_id}`);
    res.json(r[0])
  }catch(e){res.status(400).json({error:e.message})}
});


// V69 interactive dispatch movement
app.post("/api/dispatch/move-order-v69",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const {order_id,trip_id}=req.body||{};
    if(!order_id)return res.status(400).json({error:"order_id erforderlich"});
    const o=(await q(`select * from orders where id=$1`,[order_id]))[0];
    if(!o)return res.status(404).json({error:"Auftrag nicht gefunden"});
    if(!trip_id){
      await q(`update orders set planned_trip_id=null,status='new',planned_at=null where id=$1`,[order_id]);
      await audit(req,"ORDER_UNASSIGNED",`order=${order_id}`);
      return res.json({ok:true,unassigned:true})
    }
    const t=(await q(`select * from trips where id=$1 and status<>'Delivered'`,[trip_id]))[0];
    if(!t)return res.status(404).json({error:"Tour nicht gefunden"});
    if(t.dispatch_locked)return res.status(409).json({error:"Tour ist gesperrt"});
    const total=Number((await q(`select coalesce(sum(weight_kg),0) w from orders where planned_trip_id=$1 and id<>$2`,[trip_id,order_id]))[0].w)+Number(o.weight_kg||0);
    if(total>1000)return res.status(409).json({error:`Kapazität überschritten: ${total.toFixed(0)} KG`});
    const oldTrip=o.planned_trip_id;
    if(oldTrip && oldTrip!==trip_id){
      await q(`update trips set weight_kg=greatest(0,weight_kg-$1) where id=$2`,[o.weight_kg||0,oldTrip]);
      await q(`delete from trip_stops where trip_id=$1 and customer_name=(select company from customers where id=$2) and address=$3`,[oldTrip,o.customer_id,o.delivery_address]);
    }
    const pos=(await q(`select coalesce(max(dispatch_position),0)+1 n from trip_stops where trip_id=$1`,[trip_id]))[0].n;
    await q(`update orders set planned_trip_id=$1,status='planned',planned_at=now(),dispatch_position=$2 where id=$3`,[trip_id,pos,order_id]);
    await q(`update trips set weight_kg=coalesce((select sum(weight_kg) from orders where planned_trip_id=$1),0),price_net=coalesce((select sum(price_net) from orders where planned_trip_id=$1),0) where id=$1`,[trip_id]);
    const existing=await q(`select id from trip_stops where trip_id=$1 and address=$2 and customer_name=(select company from customers where id=$3)`,[trip_id,o.delivery_address,o.customer_id]);
    if(!existing.length) await q(`insert into trip_stops(trip_id,stop_order,dispatch_position,address,customer_name,planned_window_start,planned_window_end,service_minutes)
      values($1,$2,$2,$3,(select company from customers where id=$4),$5,$6,$7)`,
      [trip_id,pos,o.delivery_address,o.customer_id,o.time_window_start||null,o.time_window_end||null,o.estimated_service_min||15]);
    await audit(req,"ORDER_MOVED",`order=${order_id};trip=${trip_id}`);
    res.json({ok:true,trip_id,total_kg:total})
  }catch(e){res.status(400).json({error:e.message})}
});


// V70 interactive stop ordering + route refresh
app.post("/api/dispatch/reorder-stops-v70",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const {trip_id,stop_ids}=req.body||{};
    if(!trip_id||!Array.isArray(stop_ids))return res.status(400).json({error:"trip_id und stop_ids erforderlich"});
    const t=(await q(`select * from trips where id=$1`,[trip_id]))[0];
    if(!t)return res.status(404).json({error:"Tour nicht gefunden"});
    if(t.dispatch_locked)return res.status(409).json({error:"Tour ist gesperrt"});
    for(let i=0;i<stop_ids.length;i++) await q(`update trip_stops set dispatch_position=$1,stop_order=$1,planned_sequence=$1 where id=$2 and trip_id=$3`,[i+1,stop_ids[i],trip_id]);
    await audit(req,"STOPS_REORDERED",`trip=${trip_id};count=${stop_ids.length}`);
    res.json({ok:true})
  }catch(e){res.status(400).json({error:e.message})}
});
app.get("/api/dispatch/tour-detail-v70/:id",auth,roles("Admin","Dispatcher","Driver","Accounting"),async(req,res)=>{
  try{
    const t=(await q(`select t.*,v.name vehicle_name,v.plate,u.name driver_name from trips t left join vehicles v on v.id=t.vehicle_id left join users u on u.id=t.driver_id where t.id=$1`,[req.params.id]))[0];
    if(!t)return res.status(404).json({error:"Tour nicht gefunden"});
    const stops=await q(`select * from trip_stops where trip_id=$1 order by dispatch_position nulls last,stop_order`,[req.params.id]);
    res.json({trip:t,stops})
  }catch(e){res.status(500).json({error:e.message})}
});


// V71 route/ETA refresh after stop ordering
app.post("/api/dispatch/recalculate-route-v71/:id",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const id=req.params.id;
    const t=(await q(`select * from trips where id=$1`,[id]))[0];
    if(!t)return res.status(404).json({error:"Tour nicht gefunden"});
    const stops=await q(`select * from trip_stops where trip_id=$1 order by dispatch_position nulls last,stop_order`,[id]);
    let totalKm=0,totalMin=0;
    const points=stops.filter(x=>x.lat!=null&&x.lng!=null);
    const hav=(a,b,c,d)=>{const R=6371,rad=x=>x*Math.PI/180,la=rad(c-a),lo=rad(d-b);const z=Math.sin(la/2)**2+Math.cos(rad(a))*Math.cos(rad(c))*Math.sin(lo/2)**2;return 2*R*Math.asin(Math.sqrt(z))}
    for(let i=0;i<stops.length;i++){
      let segKm=0,segMin=0;
      if(i>0 && stops[i-1].lat!=null&&stops[i-1].lng!=null&&stops[i].lat!=null&&stops[i].lng!=null){
        segKm=hav(Number(stops[i-1].lat),Number(stops[i-1].lng),Number(stops[i].lat),Number(stops[i].lng));
        segMin=Math.max(1,Math.round(segKm/45*60));
      }
      totalKm+=segKm;totalMin+=segMin;
      await q(`update trip_stops set route_distance_from_prev_km=$1,route_duration_from_prev_min=$2,route_arrival_at=now()+($3||' minutes')::interval where id=$4`,
        [segKm,segMin,totalMin,stops[i].id]);
    }
    await q(`update trips set route_total_distance_km=$1,route_total_duration_min=$2,route_calculated_at=now(),route_provider=$3,route_eta_end_at=now()+($4||' minutes')::interval where id=$5`,
      [totalKm,totalMin,points.length===stops.length&&stops.length>1?"heuristic-v71":"partial-heuristic-v71",totalMin,id]);
    await audit(req,"ROUTE_RECALCULATED",`trip=${id};km=${totalKm.toFixed(2)};min=${totalMin}`);
    res.json({ok:true,total_distance_km:totalKm,total_duration_min:totalMin,provider:points.length===stops.length&&stops.length>1?"heuristic-v71":"partial-heuristic-v71"})
  }catch(e){res.status(400).json({error:e.message})}
});


// V72 Google Routes integration
app.post("/api/dispatch/google-route-v72/:id",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const id=req.params.id;
    const key=process.env.GOOGLE_ROUTES_API_KEY||"";
    if(!key)return res.status(503).json({error:"GOOGLE_ROUTES_API_KEY ist nicht konfiguriert"});
    const t=(await q(`select * from trips where id=$1`,[id]))[0];
    if(!t)return res.status(404).json({error:"Tour nicht gefunden"});
    const stops=await q(`select * from trip_stops where trip_id=$1 and lat is not null and lng is not null order by dispatch_position nulls last,stop_order`,[id]);
    if(stops.length<2)return res.status(400).json({error:"Mindestens zwei geokodierte Stopps erforderlich"});
    const origin={location:{latLng:{latitude:Number(stops[0].lat),longitude:Number(stops[0].lng)}}};
    const destination={location:{latLng:{latitude:Number(stops[stops.length-1].lat),longitude:Number(stops[stops.length-1].lng)}}};
    const intermediates=stops.slice(1,-1).map(x=>({location:{latLng:{latitude:Number(x.lat),longitude:Number(x.lng)}}}));
    const rr=await fetch("https://routes.googleapis.com/directions/v2:computeRoutes",{method:"POST",headers:{"Content-Type":"application/json","X-Goog-Api-Key":key,"X-Goog-FieldMask":"routes.distanceMeters,routes.duration,routes.staticDuration,routes.polyline.encodedPolyline"},body:JSON.stringify({
      origin,destination,intermediates,travelMode:"DRIVE",routingPreference:"TRAFFIC_AWARE",computeAlternativeRoutes:false
    })});
    const data=await rr.json();
    if(!rr.ok||!data.routes?.length)return res.status(502).json({error:data.error?.message||"Google Routes Fehler"});
    const route=data.routes[0], km=Number(route.distanceMeters||0)/1000, min=Math.max(1,Math.round(parseFloat(route.duration||"0s")/60));
    await q(`update trips set route_total_distance_km=$1,route_total_duration_min=$2,route_provider='google-routes-v72',route_polyline=$3,route_calculated_at=now(),route_eta_end_at=now()+($4||' minutes')::interval where id=$5`,
      [km,min,route.polyline?.encodedPolyline||null,min,id]);
    await audit(req,"GOOGLE_ROUTE_CALCULATED",`trip=${id};km=${km.toFixed(2)};min=${min}`);
    res.json({ok:true,provider:"google-routes-v72",distance_km:km,duration_min:min,polyline:route.polyline?.encodedPolyline||null})
  }catch(e){res.status(400).json({error:e.message})}
});


// V73 route map data
app.get("/api/dispatch/map-v73/:id",auth,roles("Admin","Dispatcher","Driver"),async(req,res)=>{
  try{
    const t=(await q(`select t.*,v.name vehicle_name,v.plate,u.name driver_name from trips t left join vehicles v on v.id=t.vehicle_id left join users u on u.id=t.driver_id where t.id=$1`,[req.params.id]))[0];
    if(!t)return res.status(404).json({error:"Tour nicht gefunden"});
    const stops=await q(`select id,stop_order,dispatch_position,address,customer_name,lat,lng,route_eta_at,route_arrival_at,planned_window_start,planned_window_end from trip_stops where trip_id=$1 order by dispatch_position nulls last,stop_order`,[req.params.id]);
    const gps=(await q(`select lat,lng,accuracy,created_at from gps_points where trip_id=$1 order by created_at desc limit 1`,[req.params.id]))[0]||null;
    res.json({trip:t,stops,gps})
  }catch(e){res.status(500).json({error:e.message})}
});


// V74 live map snapshot
app.get("/api/dispatch/live-map-v74/:id",auth,roles("Admin","Dispatcher","Driver"),async(req,res)=>{
  try{
    const id=req.params.id;
    const t=(await q(`select t.*,v.name vehicle_name,v.plate,u.name driver_name from trips t left join vehicles v on v.id=t.vehicle_id left join users u on u.id=t.driver_id where t.id=$1`,[id]))[0];
    if(!t)return res.status(404).json({error:"Tour nicht gefunden"});
    const stops=await q(`select s.*,row_number() over(order by s.dispatch_position nulls last,s.stop_order)::int seq from trip_stops s where s.trip_id=$1 order by s.dispatch_position nulls last,s.stop_order`,[id]);
    const gps=(await q(`select lat,lng,accuracy,created_at from gps_points where trip_id=$1 order by created_at desc limit 1`,[id]))[0]||null;
    const age=gps?Math.max(0,Math.round((Date.now()-new Date(gps.created_at).getTime())/1000)):null;
    const gps_status=!gps?"offline":age<=30?"online":age<=180?"stale":"offline";
    const active=stops.find(x=>!x.delivered_at)||null;
    let distance_km=null,eta_min=null;
    if(gps&&active&&active.lat!=null&&active.lng!=null){
      const rad=x=>x*Math.PI/180,R=6371,a=rad(Number(active.lat)-Number(gps.lat)),b=rad(Number(active.lng)-Number(gps.lng));
      const z=Math.sin(a/2)**2+Math.cos(rad(Number(gps.lat)))*Math.cos(rad(Number(active.lat)))*Math.sin(b/2)**2;
      distance_km=2*R*Math.asin(Math.sqrt(z)); eta_min=Math.max(1,Math.round(distance_km/45*60));
    }
    res.json({trip:t,stops,gps,gps_age_sec:age,gps_status,active_stop:active?{id:active.id,seq:active.seq,address:active.address,customer_name:active.customer_name}:null,distance_to_active_km:distance_km,eta_to_active_min:eta_min,server_time:new Date().toISOString()})
  }catch(e){res.status(500).json({error:e.message})}
});


// V75 live alerts
app.post("/api/dispatch/live-alerts-v75/check/:id",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const id=req.params.id;
    const t=(await q(`select * from trips where id=$1`,[id]))[0];
    if(!t)return res.status(404).json({error:"Tour nicht gefunden"});
    const gps=(await q(`select lat,lng,created_at from gps_points where trip_id=$1 order by created_at desc limit 1`,[id]))[0]||null;
    const stops=await q(`select * from trip_stops where trip_id=$1 order by dispatch_position nulls last,stop_order`,[id]);
    const now=Date.now(), age=gps?Math.round((now-new Date(gps.created_at).getTime())/1000):null;
    const open=[];
    if(!gps)open.push(["GPS_OFFLINE","critical","Kein GPS-Signal"]);
    else if(age>180)open.push(["GPS_STALE","warning",`GPS seit ${age}s nicht aktualisiert`]);
    const active=stops.find(x=>!x.delivered_at);
    if(active && active.lat!=null&&active.lng!=null&&gps){
      const rad=x=>x*Math.PI/180,R=6371,a=rad(Number(active.lat)-Number(gps.lat)),b=rad(Number(active.lng)-Number(gps.lng));
      const z=Math.sin(a/2)**2+Math.cos(rad(Number(gps.lat)))*Math.cos(rad(Number(active.lat)))*Math.sin(b/2)**2;
      const km=2*R*Math.asin(Math.sqrt(z));
      if(km<=(Number(t.arrival_radius_m||150)/1000))open.push(["GEOFENCE_REACHED","info",`Aktiver Stopp erreicht (${Math.round(km*1000)} m)`]);
    }
    const alerts=[];
    for(const [type,severity,message] of open){
      const recent=await q(`select id from control_alerts where trip_id=$1 and type=$2 and created_at>now()-interval '10 minutes' and acknowledged=false limit 1`,[id,type]);
      if(!recent.length){
        const a=(await q(`insert into control_alerts(trip_id,type,severity,message) values($1,$2,$3,$4) returning *`,[id,type,severity,message]))[0];
        alerts.push(a)
      }
    }
    const all=await q(`select * from control_alerts where trip_id=$1 and acknowledged=false order by created_at desc`,[id]);
    res.json({created:alerts,open:all})
  }catch(e){res.status(400).json({error:e.message})}
});


// V76 centralized alert center
app.get("/api/control-center/alert-center-v76",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const rows=await q(`select a.*,t.trip_number,t.priority trip_priority,t.planning_date,v.name vehicle_name,v.plate,u.name driver_name
      from control_alerts a left join trips t on t.id=a.trip_id left join vehicles v on v.id=t.vehicle_id left join users u on u.id=t.driver_id
      where a.acknowledged=false order by case a.severity when 'critical' then 1 when 'warning' then 2 else 3 end,a.created_at desc`);
    const counts=(await q(`select count(*)::int total,count(*) filter(where severity='critical')::int critical,count(*) filter(where severity='warning')::int warning,count(*) filter(where severity='info')::int info from control_alerts where acknowledged=false`))[0];
    res.json({alerts:rows,counts})
  }catch(e){res.status(500).json({error:e.message})}
});
app.post("/api/control-center/alert-center-v76/:id/ack",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const r=await q(`update control_alerts set acknowledged=true,acknowledged_at=now() where id=$1 returning *`,[req.params.id]);
    if(!r.length)return res.status(404).json({error:"Alarm nicht gefunden"});
    await audit(req,"CONTROL_ALERT_ACK",req.params.id);
    res.json(r[0])
  }catch(e){res.status(400).json({error:e.message})}
});


// V77 automatic live alert sweep
app.post("/api/control-center/alert-sweep-v77",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const trips=await q(`select id,trip_number,arrival_radius_m from trips where status in('Planned','In Transit')`);
    let created=0;
    for(const t of trips){
      const gps=(await q(`select lat,lng,created_at from gps_points where trip_id=$1 order by created_at desc limit 1`,[t.id]))[0]||null;
      const age=gps?Math.round((Date.now()-new Date(gps.created_at).getTime())/1000):null;
      const checks=[];
      if(!gps) checks.push(["GPS_OFFLINE","critical","Kein GPS-Signal"]);
      else if(age>180) checks.push(["GPS_STALE","warning",`GPS seit ${age}s nicht aktualisiert`]);
      const active=(await q(`select * from trip_stops where trip_id=$1 and delivered_at is null order by dispatch_position nulls last,stop_order limit 1`,[t.id]))[0];
      if(active&&gps&&active.lat!=null&&active.lng!=null){
        const rad=x=>x*Math.PI/180,R=6371,a=rad(Number(active.lat)-Number(gps.lat)),b=rad(Number(active.lng)-Number(gps.lng));
        const z=Math.sin(a/2)**2+Math.cos(rad(Number(gps.lat)))*Math.cos(rad(Number(active.lat)))*Math.sin(b/2)**2;
        const km=2*R*Math.asin(Math.sqrt(z));
        if(km<=Number(t.arrival_radius_m||150)/1000) checks.push(["GEOFENCE_REACHED","info",`Aktiver Stopp innerhalb ${Math.round(km*1000)} m`]);
        const eta=Math.max(1,Math.round(km/45*60));
        if(active.planned_time&&Date.now()>new Date(active.planned_time).getTime()&&km>0.5) checks.push(["ETA_EXCEEDED","warning",`Aktiver Stopp vermutlich verspätet; Entfernung ${km.toFixed(1)} KM, ETA ${eta} Min.`]);
      }
      for(const [type,severity,message] of checks){
        const exists=await q(`select id from control_alerts where trip_id=$1 and type=$2 and acknowledged=false and created_at>now()-interval '10 minutes' limit 1`,[t.id,type]);
        if(!exists.length){
          const createdAlert=(await q(`insert into control_alerts(trip_id,type,severity,message) values($1,$2,$3,$4) returning *`,[t.id,type,severity,message]))[0];
          if(severity==='critical'||severity==='warning') await v81SendPush(`Emergency Delivery · ${severity.toUpperCase()}`,message,{trip_id:t.id,alert_id:createdAlert.id,type});
          created++;
        }
      }
    }
    res.json({checked:trips.length,created})
  }catch(e){res.status(500).json({error:e.message})}
});


// V78 background live-alert worker
let v78Running=false;
async function v78SweepInternal(){
  if(v78Running)return {checked:0,created:0,skipped:true};
  v78Running=true;
  try{
    const trips=await q(`select id,arrival_radius_m from trips where status in('Planned','In Transit')`);
    let created=0;
    for(const t of trips){
      const gps=(await q(`select lat,lng,created_at from gps_points where trip_id=$1 order by created_at desc limit 1`,[t.id]))[0]||null;
      const age=gps?Math.round((Date.now()-new Date(gps.created_at).getTime())/1000):null;
      const checks=[];
      if(!gps)checks.push(["GPS_OFFLINE","critical","Kein GPS-Signal"]);
      else if(age>180)checks.push(["GPS_STALE","warning",`GPS seit ${age}s nicht aktualisiert`]);
      const active=(await q(`select * from trip_stops where trip_id=$1 and delivered_at is null order by dispatch_position nulls last,stop_order limit 1`,[t.id]))[0];
      if(active&&gps&&active.lat!=null&&active.lng!=null){
        const rad=x=>x*Math.PI/180,R=6371,a=rad(Number(active.lat)-Number(gps.lat)),b=rad(Number(active.lng)-Number(gps.lng));
        const z=Math.sin(a/2)**2+Math.cos(rad(Number(gps.lat)))*Math.cos(rad(Number(active.lat)))*Math.sin(b/2)**2;
        const km=2*R*Math.asin(Math.sqrt(z));
        if(km<=Number(t.arrival_radius_m||150)/1000)checks.push(["GEOFENCE_REACHED","info",`Aktiver Stopp innerhalb ${Math.round(km*1000)} m`]);
        if(active.planned_time&&Date.now()>new Date(active.planned_time).getTime()&&km>0.5)checks.push(["ETA_EXCEEDED","warning",`Aktiver Stopp verspätet; Entfernung ${km.toFixed(1)} KM`]);
      }
      for(const [type,severity,message] of checks){
        const exists=await q(`select id from control_alerts where trip_id=$1 and type=$2 and acknowledged=false and created_at>now()-interval '10 minutes' limit 1`,[t.id,type]);
        if(!exists.length){
          const createdAlert=(await q(`insert into control_alerts(trip_id,type,severity,message) values($1,$2,$3,$4) returning *`,[t.id,type,severity,message]))[0];
          if(severity==='critical'||severity==='warning') await v81SendPush(`Emergency Delivery · ${severity.toUpperCase()}`,message,{trip_id:t.id,alert_id:createdAlert.id,type});
          created++;
        }
      }
    }
    return {checked:trips.length,created};
  }finally{v78Running=false}
}
const v78Timer=setInterval(()=>v78SweepInternal().catch(e=>console.error("V78 alert worker:",e.message)),30000);
v78Timer.unref?.();


// V79 notification feed
app.get("/api/control-center/notifications-v79",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const since=req.query.since||new Date(Date.now()-60000).toISOString();
    const rows=await q(`select a.*,t.trip_number,v.name vehicle_name,v.plate,u.name driver_name
      from control_alerts a left join trips t on t.id=a.trip_id left join vehicles v on v.id=t.vehicle_id left join users u on u.id=t.driver_id
      where a.created_at>$1 order by a.created_at desc`,[since]);
    res.json(rows)
  }catch(e){res.status(500).json({error:e.message})}
});


// V80 browser push subscription foundation
app.post("/api/notifications/push-subscription",auth,roles("Admin","Dispatcher","Driver","Accounting"),async(req,res)=>{
  try{
    const sub=req.body?.subscription;
    if(!sub?.endpoint)return res.status(400).json({error:"subscription.endpoint fehlt"});
    await q(`create table if not exists push_subscriptions(
      id uuid primary key default gen_random_uuid(),
      user_id uuid references users(id) on delete cascade,
      endpoint text unique not null,
      subscription_json text not null,
      created_at timestamptz not null default now(),
      last_seen_at timestamptz not null default now()
    )`);
    await q(`insert into push_subscriptions(user_id,endpoint,subscription_json,last_seen_at) values($1,$2,$3,now())
      on conflict(endpoint) do update set user_id=excluded.user_id,subscription_json=excluded.subscription_json,last_seen_at=now()`,
      [req.user.id,sub.endpoint,JSON.stringify(sub)]);
    res.json({ok:true})
  }catch(e){res.status(400).json({error:e.message})}
});
app.get("/api/notifications/vapid-public-key",auth,roles("Admin","Dispatcher","Driver","Accounting"),async(req,res)=>{
  res.json({publicKey:process.env.VAPID_PUBLIC_KEY||""})
});


// V81 actual web push sender
async function v81SendPush(title,body,data={}){
  try{
    const webpush=require("web-push");
    const pub=process.env.VAPID_PUBLIC_KEY||"",priv=process.env.VAPID_PRIVATE_KEY||"",subject=process.env.VAPID_SUBJECT||"mailto:admin@example.com";
    if(!pub||!priv)return {sent:0,disabled:true};
    webpush.setVapidDetails(subject,pub,priv);
    const subs=await q(`select * from push_subscriptions where user_id in (select id from users where role in('Admin','Dispatcher') and active=true)`);
    let sent=0;
    for(const sub of subs){
      try{await webpush.sendNotification(JSON.parse(sub.subscription_json),JSON.stringify({title,body,data,tag:"emergency-delivery-alert"}));sent++}
      catch(e){if(e.statusCode===404||e.statusCode===410)await q(`delete from push_subscriptions where id=$1`,[sub.id])}
    }
    return {sent,disabled:false}
  }catch(e){console.error("V81 push:",e.message);return {sent:0,error:e.message}}
}


// V82 driver day view
app.get("/api/driver/day-v82",auth,roles("Driver"),async(req,res)=>{
  try{
    const date=req.query.date||new Date().toISOString().slice(0,10);
    const trips=await q(`select t.*,v.name vehicle_name,v.plate from trips t left join vehicles v on v.id=t.vehicle_id
      where t.driver_id=$1 and t.planning_date=$2 and t.status<>'Delivered' order by t.dispatch_slot nulls last,t.created_at`,[req.user.id,date]);
    for(const t of trips){
      t.stops=await q(`select id,stop_order,dispatch_position,address,customer_name,planned_window_start,planned_window_end,service_minutes,delivered_kg,delivered_pieces,delivered_at,lat,lng
        from trip_stops where trip_id=$1 order by dispatch_position nulls last,stop_order`,[t.id]);
    }
    res.json({date,trips})
  }catch(e){res.status(500).json({error:e.message})}
});
app.post("/api/driver/day-v82/start-trip/:id",auth,roles("Driver"),async(req,res)=>{
  try{
    const r=await q(`update trips set status='In Transit',actual_started_at=coalesce(actual_started_at,now()),live_status='online',last_driver_ping_at=now() where id=$1 and driver_id=$2 returning *`,[req.params.id,req.user.id]);
    if(!r.length)return res.status(404).json({error:"Tour nicht gefunden oder nicht zugewiesen"});
    await audit(req,"DRIVER_TRIP_STARTED",req.params.id);res.json(r[0])
  }catch(e){res.status(400).json({error:e.message})}
});


// V83 complete stop delivery workflow
app.get("/api/driver/stop-v83/:id",auth,roles("Driver"),async(req,res)=>{
  try{
    const r=await q(`select s.*,t.trip_number,t.driver_id,t.status trip_status,t.vehicle_id from trip_stops s join trips t on t.id=s.trip_id where s.id=$1 and t.driver_id=$2`,[req.params.id,req.user.id]);
    if(!r.length)return res.status(404).json({error:"Stopp nicht gefunden"});
    res.json(r[0])
  }catch(e){res.status(500).json({error:e.message})}
});
app.post("/api/driver/stop-v83/:id/arrive",auth,roles("Driver"),async(req,res)=>{
  try{
    const r=await q(`update trip_stops s set planned_time=coalesce(planned_time,now()) from trips t
      where s.id=$1 and t.id=s.trip_id and t.driver_id=$2 returning s.*`,[req.params.id,req.user.id]);
    if(!r.length)return res.status(404).json({error:"Stopp nicht gefunden"});
    await audit(req,"V83_STOP_ARRIVED",req.params.id);res.json(r[0])
  }catch(e){res.status(400).json({error:e.message})}
});
app.post("/api/driver/stop-v83/:id/deliver",auth,roles("Driver"),async(req,res)=>{
  try{
    const {kg,pieces,note,photo,signature,lat,lng,accuracy}=req.body||{};
    const stop=(await q(`select s.*,t.id trip_id,t.driver_id from trip_stops s join trips t on t.id=s.trip_id where s.id=$1 and t.driver_id=$2`,[req.params.id,req.user.id]))[0];
    if(!stop)return res.status(404).json({error:"Stopp nicht gefunden"});
    if(!(Number(kg)>=0)||!(Number(pieces)>=0))return res.status(400).json({error:"KG und Stück müssen gültig sein"});
    const r=await q(`update trip_stops set delivered_kg=$1,delivered_pieces=$2,delivery_note=$3,delivery_photo=$4,signature_data=$5,
      proof_lat=$6,proof_lng=$7,proof_accuracy=$8,proof_at=now(),delivered_at=now() where id=$9 returning *`,
      [kg,pieces,note||"",photo||null,signature||null,lat||null,lng||null,accuracy||null,req.params.id]);
    const open=await q(`select count(*)::int n from trip_stops where trip_id=$1 and delivered_at is null`,[stop.trip_id]);
    if(open[0].n===0)await q(`update trips set status='Delivered',actual_finished_at=now(),live_status='offline',updated_at=now() where id=$1`,[stop.trip_id]);
    await audit(req,"V83_STOP_DELIVERED",req.params.id);
    res.json({stop:r[0],trip_completed:open[0].n===0,next:open[0].n?await q(`select id,address,customer_name from trip_stops where trip_id=$1 and delivered_at is null order by dispatch_position nulls last,stop_order limit 1`,[stop.trip_id]):[]})
  }catch(e){res.status(400).json({error:e.message})}
});


// V84 touch signature + proof bundle
app.post("/api/driver/stop-v84/signature",auth,roles("Driver"),async(req,res)=>{
  try{
    const {signature_data}=req.body||{};
    if(!signature_data||!String(signature_data).startsWith("data:image/"))return res.status(400).json({error:"Ungültige Signatur"});
    const r=await q(`update trip_stops s set signature_data=$1 where s.id=$2 and exists(select 1 from trips t where t.id=s.trip_id and t.driver_id=$3) returning s.id,signature_data`,[signature_data,req.params.id,req.user.id]);
    if(!r.length)return res.status(404).json({error:"Stopp nicht gefunden"});
    await audit(req,"V84_SIGNATURE_SAVED",req.params.id);res.json({ok:true})
  }catch(e){res.status(400).json({error:e.message})}
});
app.get("/api/driver/stop-v84/proof-bundle/:id",auth,roles("Driver","Admin","Dispatcher","Accounting"),async(req,res)=>{
  try{
    const r=await q(`select s.*,t.trip_number,t.driver_id,t.vehicle_id,v.name vehicle_name,v.plate,c.company customer_company
      from trip_stops s join trips t on t.id=s.trip_id left join vehicles v on v.id=t.vehicle_id
      left join customers c on c.id=t.customer_id where s.id=$1 and ($2 in('Admin','Dispatcher','Accounting') or t.driver_id=$3)`,[req.params.id,req.user.role,req.user.id]);
    if(!r.length)return res.status(404).json({error:"Nachweis nicht gefunden"});
    res.json(r[0])
  }catch(e){res.status(500).json({error:e.message})}
});


// V85 printable delivery note / proof document
app.get("/api/driver/stop-v85/ddt/:id",auth,roles("Driver","Admin","Dispatcher","Accounting"),async(req,res)=>{
  try{
    const r=await q(`select t.*,c.company customer_company,c.vat_id customer_vat,c.address customer_address,c.city customer_city,
      u.name driver_name,v.name vehicle_name,v.plate
      from trips t left join customers c on c.id=t.customer_id left join users u on u.id=t.driver_id left join vehicles v on v.id=t.vehicle_id
      where t.id=(select trip_id from trip_stops where id=$1) and ($2 in('Admin','Dispatcher','Accounting') or t.driver_id=$3)`,[req.params.id,req.user.role,req.user.id]);
    if(!r.length)return res.status(404).json({error:"Tour nicht gefunden"});
    const t=r[0],stops=await q(`select * from trip_stops where trip_id=$1 order by dispatch_position nulls last,stop_order`,[t.id]);
    res.json({trip:t,stops})
  }catch(e){res.status(500).json({error:e.message})}
});


// V86 automatic document chain: DDT -> invoice -> email queue
app.post("/api/trips/:id/complete-document-chain-v86",auth,roles("Admin","Dispatcher","Accounting"),async(req,res)=>{
  try{
    const trip=(await q(`select * from trips where id=$1`,[req.params.id]))[0];
    if(!trip)return res.status(404).json({error:"Tour nicht gefunden"});
    const open=await q(`select count(*)::int n from trip_stops where trip_id=$1 and delivered_at is null`,[trip.id]);
    if(open[0].n>0)return res.status(400).json({error:"Noch nicht alle Stopps zugestellt"});
    let ddt=(await q(`select * from delivery_documents where trip_id=$1`,[trip.id]))[0];
    if(!ddt){
      const num=`DDT-${new Date().toISOString().slice(0,10).replaceAll('-','')}-${String(Date.now()).slice(-6)}`;
      ddt=(await q(`insert into delivery_documents(trip_id,document_number,status,proof_complete) values($1,$2,'Completed',true) returning *`,[trip.id,num]))[0];
    }
    let invoice=null;
    if(Number(trip.price_net||0)>0){
      invoice=(await q(`select * from invoices where trip_id=$1`,[trip.id]))[0];
      if(!invoice){
        const net=Number(trip.price_net),vatRate=22,vat=+(net*vatRate/100).toFixed(2),gross=+(net+vat).toFixed(2);
        const invNo=`INV-${new Date().getFullYear()}-${String(Date.now()).slice(-7)}`;
        const due=new Date(Date.now()+30*86400000).toISOString().slice(0,10);
        invoice=(await q(`insert into invoices(invoice_number,customer_id,trip_id,due_date,net,vat_rate,vat,gross,status,currency,payment_terms_days,description)
          values($1,$2,$3,$4,$5,$6,$7,$8,'Open','EUR',30,$9) returning *`,
          [invNo,trip.customer_id,trip.id,due,net,vatRate,vat,gross,`Transport Tour ${trip.trip_number}`]))[0];
      }
    }
    const cust=(await q(`select email,company from customers where id=$1`,[trip.customer_id]))[0];
    let email=null;
    if(cust?.email){
      const existing=await q(`select * from email_outbox where invoice_id=$1 and delivery_document_id=$2 limit 1`,[invoice?.id||null,ddt.id]).catch(()=>[]);
      if(!existing.length){
        email=(await q(`insert into email_outbox(customer_id,invoice_id,delivery_document_id,recipient,subject,body_html)
          values($1,$2,$3,$4,$5,$6) returning *`,
          [trip.customer_id,invoice?.id||null,ddt.id,cust.email,`Dokumente ${trip.trip_number} – Emergency Delivery`,
           `<p>Guten Tag ${cust.company||''},</p><p>anbei erhalten Sie die Transportdokumente zur Tour ${trip.trip_number}.</p><p>Lieferschein: ${ddt.document_number}${invoice?` · Rechnung: ${invoice.invoice_number}`:""}</p>`]))[0];
      }else email=existing[0];
    }
    await audit(req,"V86_DOCUMENT_CHAIN",`${trip.id} DDT=${ddt.document_number} invoice=${invoice?.invoice_number||"none"} email=${email?.recipient||"none"}`);
    res.json({ok:true,trip_id:trip.id,ddt,invoice,email})
  }catch(e){res.status(400).json({error:e.message})}
});


// V87 PDF document generation + attachment queue
function v87Money(n){return Number(n||0).toFixed(2)+" EUR"}
async function v185PdfLogo(doc,company={}){
  try{
    const p=require("path").join(__dirname,"public","assets","emergency-delivery-logo.png");
    const fs=require("fs");
    if(fs.existsSync(p)) doc.image(p,48,24,{fit:[170,88],align:"left",valign:"top"});
    const lines=[company.company_name||"Emergency Delivery",[company.address,company.postal_code,company.city].filter(Boolean).join(", "),company.country||"",company.phone?`Tel. ${company.phone}`:"",company.email||"",company.website||""];
    doc.font("Helvetica-Bold").fontSize(10).fillColor("#172033").text(lines[0],330,34,{width:215,align:"left"});
    doc.font("Helvetica").fontSize(8.5);
    lines.slice(1).filter(Boolean).forEach((line,i)=>doc.text(line,330,50+i*12,{width:215}));
    doc.save();doc.strokeColor("#d6a33a").lineWidth(1.2).moveTo(48,118).lineTo(547,118).stroke();doc.restore();
  }catch(_){}
  doc.y=Math.max(doc.y,128);
}
function v189DateOnly(value){
  if(!value)return "";
  const s=String(value);
  if(/^\d{4}-\d{2}-\d{2}/.test(s))return s.slice(0,10);
  const d=new Date(value);
  return Number.isNaN(d.getTime())?s:d.toISOString().slice(0,10);
}
function v189Cell(value){
  return String(value??"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}
async function v87BuildInvoicePdf(inv){
  const PDFDocument=require("pdfkit"); const chunks=[]; const doc=new PDFDocument({size:"A4",margin:48});
  doc.on("data",c=>chunks.push(c)); const done=new Promise(r=>doc.on("end",r));
  const company=(await q("select * from company_settings where id=1"))[0]||{};
  v185PdfLogo(doc,company);

  doc.fontSize(20).font("Helvetica-Bold").text(company.company_name||"Emergency Delivery");
  doc.moveDown(0.35).fontSize(18).text("RECHNUNG");
  doc.moveDown(0.7).font("Helvetica").fontSize(10);

  const infoTop=doc.y;
  doc.rect(48,infoTop,499,70).strokeColor("#d0d5dd").stroke();
  doc.font("Helvetica-Bold").text("Rechnungsdaten",60,infoTop+12);
  doc.font("Helvetica").text(`Rechnungsnummer: ${inv.invoice_number||"—"}`,60,infoTop+30);
  doc.text(`Rechnungsdatum: ${v189DateOnly(inv.issue_date)||"—"}`,60,infoTop+46);
  doc.text(`Fälligkeitsdatum: ${v189DateOnly(inv.due_date)||"—"}`,310,infoTop+30);
  doc.text(`Status: ${inv.status||"—"}`,310,infoTop+46);
  doc.y=infoTop+84;

  const customerTop=doc.y;
  doc.rect(48,customerTop,499,78).strokeColor("#d0d5dd").stroke();
  doc.font("Helvetica-Bold").text("Kunde",60,customerTop+12);
  doc.font("Helvetica").text(inv.customer_company||"—",60,customerTop+30);
  doc.text(inv.customer_vat||"",60,customerTop+46);
  doc.text(`Tour: ${inv.trip_number||"—"}`,310,customerTop+30);
  doc.y=customerTop+92;

  const tableTop=doc.y;
  const x=[48,350,415,481,547];
  const widths=[302,65,66,66];
  doc.rect(48,tableTop,499,28).fillAndStroke("#f2f4f7","#d0d5dd");
  doc.fillColor("#172033").font("Helvetica-Bold").fontSize(9);
  doc.text("Leistung / Beschreibung",58,tableTop+9);
  doc.text("Netto",x[1]+6,tableTop+9,{width:50,align:"right"});
  doc.text("MwSt.",x[2]+6,tableTop+9,{width:50,align:"right"});
  doc.text("Brutto",x[3]+6,tableTop+9,{width:55,align:"right"});
  doc.fillColor("#172033").font("Helvetica").fontSize(9);
  doc.rect(48,tableTop+28,499,40).strokeColor("#d0d5dd").stroke();
  doc.text(inv.description||"Transportleistung",58,tableTop+43,{width:285});
  doc.text(v87Money(inv.net),x[1]+6,tableTop+43,{width:50,align:"right"});
  doc.text(`${Number(inv.vat_rate||0).toFixed(2)}%`,x[2]+6,tableTop+43,{width:50,align:"right"});
  doc.text(v87Money(inv.gross),x[3]+6,tableTop+43,{width:55,align:"right"});
  doc.y=tableTop+84;

  const sumTop=doc.y;
  doc.rect(300,sumTop,247,92).strokeColor("#d0d5dd").stroke();
  doc.font("Helvetica").fontSize(10).text("Nettobetrag",315,sumTop+14);
  doc.text(v87Money(inv.net),420,sumTop+14,{width:110,align:"right"});
  doc.text(`MwSt. ${Number(inv.vat_rate||0).toFixed(2)}%`,315,sumTop+35);
  doc.text(v87Money(inv.vat),420,sumTop+35,{width:110,align:"right"});
  doc.font("Helvetica-Bold").fontSize(12).text("Gesamtbetrag",315,sumTop+62);
  doc.text(v87Money(inv.gross),420,sumTop+62,{width:110,align:"right"});
  doc.y=sumTop+110;
  doc.font("Helvetica").fontSize(8).fillColor("#667085").text("Rechnungsdatum und Fälligkeit werden ohne Uhrzeit ausgewiesen.");
  const footer=[company.company_name,company.legal_name, [company.address,company.postal_code,company.city].filter(Boolean).join(", "), company.vat_id?`P.IVA: ${company.vat_id}`:"", company.iban?`IBAN: ${company.iban}`:"", company.footer_note||""];
  doc.moveDown(1).fillColor("#172033").fontSize(7).text(footer.filter(Boolean).join(" · "),48,doc.page.height-52,{width:499,align:"center"});
  doc.end(); await done; return Buffer.concat(chunks)
}
async function v87BuildDdtPdf(t,stops,ddt){
  const PDFDocument=require("pdfkit"); const chunks=[]; const doc=new PDFDocument({size:"A4",margin:48});
  doc.on("data",c=>chunks.push(c)); const done=new Promise(r=>doc.on("end",r));
  const company=(await q("select * from company_settings where id=1"))[0]||{};
  v185PdfLogo(doc,company);

  doc.fontSize(20).font("Helvetica-Bold").text(company.company_name||"Emergency Delivery");
  doc.moveDown(0.35).fontSize(18).text("LIEFERSCHEIN");
  doc.moveDown(0.7).font("Helvetica").fontSize(10);

  const infoTop=doc.y;
  doc.rect(48,infoTop,499,92).strokeColor("#d0d5dd").stroke();
  doc.font("Helvetica-Bold").text("Lieferscheindaten",60,infoTop+12);
  doc.font("Helvetica").text(`Lieferscheinnummer: ${ddt.document_number||"—"}`,60,infoTop+30);
  doc.text(`Datum: ${v189DateOnly(ddt.issued_at)||v189DateOnly(new Date())}`,60,infoTop+46);
  doc.text(`Tour: ${t.trip_number||"—"}`,310,infoTop+30);
  doc.text(`Status: ${ddt.status||"—"}`,310,infoTop+46);
  doc.font("Helvetica-Bold").text("Kunde",60,infoTop+66);
  doc.font("Helvetica").text(t.customer_company||"—",110,infoTop+66,{width:420});
  doc.y=infoTop+108;

  const tableTop=doc.y;
  const cols=[48,78,250,410,474,547];
  doc.rect(48,tableTop,499,30).fillAndStroke("#f2f4f7","#d0d5dd");
  doc.fillColor("#172033").font("Helvetica-Bold").fontSize(8);
  doc.text("Pos.",54,tableTop+10,{width:20});
  doc.text("Empfänger",82,tableTop+10,{width:160});
  doc.text("Lieferadresse",254,tableTop+10,{width:150});
  doc.text("KG",414,tableTop+10,{width:45,align:"right"});
  doc.text("Stück",478,tableTop+10,{width:55,align:"right"});

  let y=tableTop+30;
  doc.font("Helvetica").fontSize(8);
  const rows=stops.length?stops:[{customer_name:t.customer_company||"—",address:"",delivered_kg:t.weight_kg||0,delivered_pieces:t.pieces||0,status:t.status||"—"}];
  rows.forEach((x,i)=>{
    const h=42;
    if(y+h>doc.page.height-90){doc.addPage(); y=60;}
    doc.rect(48,y,499,h).strokeColor("#d0d5dd").stroke();
    doc.fillColor("#172033");
    doc.text(String(i+1),54,y+14,{width:20});
    doc.text(x.customer_name||"—",82,y+9,{width:160,height:28,ellipsis:true});
    doc.text(x.address||"—",254,y+9,{width:150,height:28,ellipsis:true});
    doc.text(String(x.delivered_kg??0),414,y+14,{width:45,align:"right"});
    doc.text(String(x.delivered_pieces??0),478,y+14,{width:55,align:"right"});
    y+=h;
  });
  y+=18;
  doc.font("Helvetica-Bold").fontSize(10).text("Transportdaten",48,y);
  doc.font("Helvetica").fontSize(9).text(`Fahrer: ${t.driver_name||"—"}`,48,y+18);
  doc.text(`Fahrzeug: ${[t.vehicle_name,t.plate].filter(Boolean).join(" · ")||"—"}`,280,y+18);
  doc.moveDown(3).fontSize(8).fillColor("#667085").text("Der Lieferschein enthält keine Uhrzeiten.");
  const footer=[company.company_name,company.legal_name,[company.address,company.postal_code,company.city].filter(Boolean).join(", "),company.vat_id?`P.IVA: ${company.vat_id}`:"",company.phone?`Tel. ${company.phone}`:"",company.email||"",company.footer_note||""];
  doc.moveDown(1).fillColor("#172033").fontSize(7).text(footer.filter(Boolean).join(" · "),48,doc.page.height-52,{width:499,align:"center"});
  doc.end(); await done; return Buffer.concat(chunks)
}

// V181 – direkte PDF-Downloads für DDT und Rechnungen
function v181Filename(name){return String(name||"dokument").replace(/[^a-zA-Z0-9._-]+/g,"_")}
app.get("/api/documents/invoice/:id/pdf",auth,async(req,res)=>{
  try{
    const inv=(await q(`select i.*,c.company customer_company,c.vat_id customer_vat,t.trip_number
      from invoices i left join customers c on c.id=i.customer_id left join trips t on t.id=i.trip_id
      where i.id=$1`,[req.params.id]))[0];
    if(!inv)return res.status(404).json({error:"Rechnung nicht gefunden"});
    const pdf=await v87BuildInvoicePdf(inv);
    res.set("Content-Type","application/pdf");
    res.set("Content-Disposition",`attachment; filename="${v181Filename(inv.invoice_number)}.pdf"`);
    res.send(pdf);
  }catch(e){res.status(500).json({error:e.message})}
});
app.get("/api/documents/ddt/:id/pdf",auth,async(req,res)=>{
  await q(`CREATE TABLE IF NOT EXISTS delivery_documents(
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    trip_id uuid UNIQUE REFERENCES trips(id) ON DELETE CASCADE,
    document_number text UNIQUE NOT NULL,
    issued_at timestamptz DEFAULT now(),
    status text DEFAULT 'Open',
    proof_complete boolean DEFAULT false
  )`);

  try{
    const t=(await q(`select t.*,c.company customer_company,c.vat_id customer_vat,
      u.name driver_name,v.name vehicle_name,v.plate
      from trips t left join customers c on c.id=t.customer_id
      left join users u on u.id=t.driver_id left join vehicles v on v.id=t.vehicle_id
      where t.id=$1`,[req.params.id]))[0];
    if(!t)return res.status(404).json({error:"Auftrag/Tour nicht gefunden"});
    let ddt=(await q("select * from delivery_documents where trip_id=$1",[t.id]))[0];
    if(!ddt){
      const n=await q(`select 'DDT-'||extract(year from current_date)::int||'-'||lpad(
        (coalesce(max(cast(split_part(document_number,'-',3) as int)),0)+1)::text,4,'0') n
        from delivery_documents`);
      ddt=(await q("insert into delivery_documents(trip_id,document_number,proof_complete,status) values($1,$2,$3,$4) returning *",
        [t.id,n[0].n,t.status==="Delivered",t.status==="Delivered"?"Completed":"Open"]))[0];
    }
    const stops=await q("select * from trip_stops where trip_id=$1 order by stop_order",[t.id]);
    const pdf=await v87BuildDdtPdf(t,stops,ddt);
    res.set("Content-Type","application/pdf");
    res.set("Content-Disposition",`attachment; filename="${v181Filename(ddt.document_number)}.pdf"`);
    res.send(pdf);
  }catch(e){res.status(500).json({error:e.message})}
});

app.post("/api/documents/send-pdf-v87/:tripId",auth,roles("Admin","Dispatcher","Accounting"),async(req,res)=>{
  try{
    const trip=(await q(`select t.*,c.company customer_company,c.vat_id customer_vat,c.email customer_email,u.name driver_name,v.name vehicle_name,v.plate from trips t left join customers c on c.id=t.customer_id left join users u on u.id=t.driver_id left join vehicles v on v.id=t.vehicle_id where t.id=$1`,[req.params.tripId]))[0];
    if(!trip)return res.status(404).json({error:"Tour nicht gefunden"});
    const ddt=(await q(`select * from delivery_documents where trip_id=$1`,[trip.id]))[0];
    const inv=(await q(`select i.*,c.company customer_company,c.vat_id customer_vat from invoices i left join customers c on c.id=i.customer_id where i.trip_id=$1`,[trip.id]))[0];
    if(!ddt&&!inv)return res.status(400).json({error:"Keine Dokumente vorhanden"});
    if(!trip.customer_email)return res.status(400).json({error:"Kunden-E-Mail fehlt"});
    const stops=await q(`select * from trip_stops where trip_id=$1 order by dispatch_position nulls last,stop_order`,[trip.id]);
    const attachments=[];
    if(inv){const b=await v87BuildInvoicePdf(inv);attachments.push({filename:`${inv.invoice_number}.pdf`,content:b.toString("base64")})}
    if(ddt){const b=await v87BuildDdtPdf(trip,stops,ddt);attachments.push({filename:`${ddt.document_number}.pdf`,content:b.toString("base64")})}
    const body=`<p>Guten Tag ${trip.customer_company||""},</p><p>anbei erhalten Sie DDT und Rechnung zur Tour ${trip.trip_number}.</p>`;
    const row=(await q(`insert into email_outbox(customer_id,invoice_id,delivery_document_id,recipient,subject,body_html) values($1,$2,$3,$4,$5,$6) returning *`,
      [trip.customer_id,inv?.id||null,ddt?.id||null,trip.customer_email,`Dokumente ${trip.trip_number} – Emergency Delivery`,body]))[0];
    // Store attachment payload only if the existing schema supports a column.
    await q(`alter table email_outbox add column if not exists attachments_json text`).catch(()=>{});
    await q(`update email_outbox set attachments_json=$1 where id=$2`,[JSON.stringify(attachments),row.id]);
    await audit(req,"V87_DOCUMENT_PDF_QUEUE",`${trip.id} ${attachments.map(a=>a.filename).join(",")}`);
    res.json({ok:true,outbox_id:row.id,attachments:attachments.map(a=>a.filename)})
  }catch(e){res.status(400).json({error:e.message})}
});


// V88 SMTP worker with PDF attachments and retries
let v88MailRunning=false;
async function v88SendMail(row){
  const nodemailer=require("nodemailer");
  const host=process.env.SMTP_HOST,port=Number(process.env.SMTP_PORT||587),user=process.env.SMTP_USER,pass=process.env.SMTP_PASS;
  if(!host)throw new Error("SMTP_HOST nicht konfiguriert");
  const transporter=nodemailer.createTransport({host,port,secure:String(process.env.SMTP_SECURE||"false")==="true",auth:user?{user,pass}:undefined});
  const attachments=(JSON.parse(row.attachments_json||"[]")).map(a=>({filename:a.filename,content:Buffer.from(a.content,"base64"),contentType:"application/pdf"}));
  await transporter.sendMail({from:process.env.SMTP_FROM||user,to:row.recipient,subject:row.subject,html:row.body_html,attachments});
}
async function v88MailSweep(){
  if(v88MailRunning)return; v88MailRunning=true;
  try{
    await q(`alter table email_outbox add column if not exists attachments_json text`);
    const rows=await q(`select * from email_outbox where status in('Queued','Retry') and attempts<5 order by queued_at asc limit 10`);
    for(const row of rows){
      try{
        await q(`update email_outbox set status='Sending',attempts=attempts+1 where id=$1`,[row.id]);
        await v88SendMail(row);
        await q(`update email_outbox set status='Sent',sent_at=now(),customer_notified_at=now(),last_error=null where id=$1`,[row.id]);
        if(row.invoice_id)await q(`update invoices set sent_at=now() where id=$1`,[row.invoice_id]);
        if(row.delivery_document_id)await q(`update delivery_documents set sent_at=now() where id=$1`,[row.delivery_document_id]);
        if(row.dunning_id)await q(`update invoice_dunning set status='Sent',sent_at=now() where id=$1`,[row.dunning_id]);
      }catch(e){
        const n=Number(row.attempts||0)+1;
        await q(`update email_outbox set status=$1,last_error=$2 where id=$3`,[n>=5?'Failed':'Retry',String(e.message).slice(0,1000),row.id]);
      }
    }
  }catch(e){console.error("V88 SMTP worker:",e.message)} finally{v88MailRunning=false}
}
setInterval(()=>v88MailSweep().catch(e=>console.error(e)),30000);


app.get("/api/documents/email-status-v88",auth,roles("Admin","Dispatcher","Accounting"),async(req,res)=>{
  try{res.json(await q(`select id,recipient,subject,status,attempts,last_error,queued_at,sent_at from email_outbox order by queued_at desc limit 100`))}
  catch(e){res.status(500).json({error:e.message})}
});


// V89 automatic customer document delivery after successful completion
async function v89QueueCustomerDocuments(tripId){
  const trip=(await q(`select t.*,c.email customer_email,c.company customer_company from trips t left join customers c on c.id=t.customer_id where t.id=$1`,[tripId]))[0];
  if(!trip||!trip.customer_email)return {queued:false,reason:"no_customer_email"};
  const ddt=(await q(`select * from delivery_documents where trip_id=$1`,[tripId]))[0];
  const inv=(await q(`select * from invoices where trip_id=$1`,[tripId]))[0];
  if(!ddt&&!inv)return {queued:false,reason:"no_documents"};
  await q(`alter table email_outbox add column if not exists delivery_reason text`);
  await q(`alter table email_outbox add column if not exists customer_notified_at timestamptz`);
  const subject=`Transportdokumente ${trip.trip_number} – Emergency Delivery`;
  const existing=await q(`select id,status from email_outbox where customer_id=$1 and delivery_document_id is not distinct from $2 and invoice_id is not distinct from $3 and delivery_reason='automatic_completion' order by queued_at desc limit 1`,
    [trip.customer_id,ddt?.id||null,inv?.id||null]);
  if(existing.length)return {queued:false,reason:"already_queued",outbox_id:existing[0].id};
  const body=`<p>Guten Tag ${trip.customer_company||""},</p><p>Ihre Transporttour ${trip.trip_number} wurde erfolgreich abgeschlossen.</p><p>Die zugehörigen Transportdokumente befinden sich im Anhang.</p>`;
  const row=(await q(`insert into email_outbox(customer_id,invoice_id,delivery_document_id,recipient,subject,body_html,status,delivery_reason)
    values($1,$2,$3,$4,$5,$6,'Queued','automatic_completion') returning id`,
    [trip.customer_id,inv?.id||null,ddt?.id||null,trip.customer_email,subject,body]))[0];
  return {queued:true,outbox_id:row.id,recipient:trip.customer_email};
}
app.post("/api/trips/:id/auto-customer-delivery-v89",auth,roles("Admin","Dispatcher","Accounting"),async(req,res)=>{
  try{res.json(await v89QueueCustomerDocuments(req.params.id))}
  catch(e){res.status(400).json({error:e.message})}
});
app.get("/api/customers/:id/document-delivery-v89",auth,roles("Admin","Dispatcher","Accounting"),async(req,res)=>{
  try{
    await q(`alter table email_outbox add column if not exists customer_notified_at timestamptz`);
    const rows=await q(`select id,recipient,subject,status,attempts,last_error,queued_at,sent_at,customer_notified_at,delivery_reason
      from email_outbox where customer_id=$1 order by queued_at desc limit 100`,[req.params.id]);
    res.json(rows)
  }catch(e){res.status(500).json({error:e.message})}
});


// V90 customer 360 communication center
app.get("/api/customers/:id/360-v90",auth,roles("Admin","Dispatcher","Accounting"),async(req,res)=>{
  try{
    const c=(await q(`select * from customers where id=$1`,[req.params.id]))[0];
    if(!c)return res.status(404).json({error:"Kunde nicht gefunden"});
    const [orders,trips,invoices,ddts,emails]=await Promise.all([
      q(`select * from orders where customer_id=$1 order by created_at desc limit 100`,[c.id]),
      q(`select t.id,t.trip_number,t.status,t.planning_date,t.price_net,t.weight_kg,t.vehicle_id,t.driver_id,u.name driver_name,v.name vehicle_name,v.plate
         from trips t left join users u on u.id=t.driver_id left join vehicles v on v.id=t.vehicle_id where t.customer_id=$1 order by t.created_at desc limit 100`,[c.id]),
      q(`select id,invoice_number,trip_id,issue_date,due_date,net,vat,gross,status,currency,sent_at,paid_at from invoices where customer_id=$1 order by issue_date desc limit 100`,[c.id]),
      q(`select d.*,t.trip_number from delivery_documents d join trips t on t.id=d.trip_id where t.customer_id=$1 order by d.issued_at desc limit 100`,[c.id]),
      q(`select id,recipient,subject,status,attempts,last_error,queued_at,sent_at,customer_notified_at,delivery_reason from email_outbox where customer_id=$1 order by queued_at desc limit 100`,[c.id])
    ]);
    const outstanding=invoices.filter(x=>x.status!=="Paid").reduce((a,x)=>a+Number(x.gross||0),0);
    const billed=invoices.reduce((a,x)=>a+Number(x.gross||0),0);
    res.json({customer:c,orders,trips,invoices,ddts,emails,summary:{billed,outstanding,orders:orders.length,trips:trips.length,ddts:ddts.length,emails:emails.length}})
  }catch(e){res.status(500).json({error:e.message})}
});


// V91 interactive customer center
app.get("/api/customers/interactive-v91",auth,roles("Admin","Dispatcher","Accounting"),async(req,res)=>{
  try{res.json(await q(`select id,company,vat_id,address,city,email,phone from customers order by company`))}
  catch(e){res.status(500).json({error:e.message})}
});
app.post("/api/invoices/:id/status-v91",auth,roles("Admin","Accounting"),async(req,res)=>{
  try{
    const status=String(req.body?.status||"Open");
    if(!["Open","Paid","Overdue"].includes(status))return res.status(400).json({error:"Ungültiger Status"});
    const r=await q(`update invoices set status=$1,paid_at=case when $1='Paid' then coalesce(paid_at,now()) else null end where id=$2 returning *`,[status,req.params.id]);
    if(!r.length)return res.status(404).json({error:"Rechnung nicht gefunden"});
    await audit(req,"V91_INVOICE_STATUS",`${r[0].invoice_number}=${status}`);res.json(r[0])
  }catch(e){res.status(400).json({error:e.message})}
});


// V92 receivables / partial payments
app.post("/api/invoices/:id/payment-v92",auth,roles("Admin","Accounting"),async(req,res)=>{
  try{
    await q(`create table if not exists invoice_payments(
      id uuid primary key default gen_random_uuid(),
      invoice_id uuid not null references invoices(id) on delete cascade,
      payment_date date not null default current_date,
      amount numeric not null check(amount>0),
      method text,
      reference text,
      note text,
      created_at timestamptz not null default now()
    )`);
    const amount=Number(req.body?.amount),method=req.body?.method||"",reference=req.body?.reference||"",note=req.body?.note||"";
    if(!(amount>0))return res.status(400).json({error:"Zahlungsbetrag muss > 0 sein"});
    const inv=(await q(`select * from invoices where id=$1`,[req.params.id]))[0];
    if(!inv)return res.status(404).json({error:"Rechnung nicht gefunden"});
    const paid=(await q(`select coalesce(sum(amount),0) total from invoice_payments where invoice_id=$1`,[inv.id]))[0].total;
    const remaining=Number(inv.gross)-Number(paid);
    if(amount>remaining+0.001)return res.status(400).json({error:`Zahlung zu hoch. Offen: ${remaining.toFixed(2)} EUR`});
    const p=(await q(`insert into invoice_payments(invoice_id,amount,method,reference,note) values($1,$2,$3,$4,$5) returning *`,[inv.id,amount,method,reference,note]))[0];
    const newPaid=Number(paid)+amount;
    const status=newPaid>=Number(inv.gross)-0.001?"Paid":(inv.due_date && new Date(inv.due_date)<new Date()?"Overdue":"Open");
    await q(`update invoices set status=$1,paid_at=case when $1='Paid' then coalesce(paid_at,now()) else null end where id=$2`,[status,inv.id]);
    await audit(req,"V92_PAYMENT",`${inv.invoice_number} ${amount.toFixed(2)} EUR ${status}`);
    res.json({payment:p,status,paid_total:newPaid,remaining:Math.max(0,Number(inv.gross)-newPaid)})
  }catch(e){res.status(400).json({error:e.message})}
});
app.get("/api/invoices/receivables-v92",auth,roles("Admin","Accounting","Dispatcher"),async(req,res)=>{
  try{
    await q(`create table if not exists invoice_payments(
      id uuid primary key default gen_random_uuid(), invoice_id uuid not null references invoices(id) on delete cascade,
      payment_date date not null default current_date, amount numeric not null check(amount>0), method text, reference text, note text, created_at timestamptz not null default now())`);
    const rows=await q(`select i.id,i.invoice_number,i.issue_date,i.due_date,i.gross,i.status,i.sent_at,c.company customer_company,c.email,
      coalesce(sum(p.amount),0) paid_total
      from invoices i left join customers c on c.id=i.customer_id left join invoice_payments p on p.invoice_id=i.id
      group by i.id,c.company,c.email order by i.due_date nulls last,i.issue_date desc`);
    res.json(rows.map(x=>({...x,remaining:Math.max(0,Number(x.gross)-Number(x.paid_total)),computed_status:(Number(x.paid_total)>=Number(x.gross)-.001?"Paid":(x.due_date&&new Date(x.due_date)<new Date()?"Overdue":"Open"))})))
  }catch(e){res.status(500).json({error:e.message})}
});
app.get("/api/invoices/:id/payments-v92",auth,roles("Admin","Accounting","Dispatcher"),async(req,res)=>{
  try{await q(`create table if not exists invoice_payments(id uuid primary key default gen_random_uuid(),invoice_id uuid not null references invoices(id) on delete cascade,payment_date date not null default current_date,amount numeric not null check(amount>0),method text,reference text,note text,created_at timestamptz not null default now())`);res.json(await q(`select * from invoice_payments where invoice_id=$1 order by payment_date desc,created_at desc`,[req.params.id]))}
  catch(e){res.status(500).json({error:e.message})}
});


// V93 dunning management
app.post("/api/invoices/:id/dunning-v93",auth,roles("Admin","Accounting"),async(req,res)=>{
  try{
    await q(`create table if not exists invoice_dunning(
      id uuid primary key default gen_random_uuid(),
      invoice_id uuid not null references invoices(id) on delete cascade,
      level integer not null default 1,
      dunning_date date not null default current_date,
      status text not null default 'Open',
      recipient text,
      sent_at timestamptz,
      note text,
      created_at timestamptz not null default now()
    )`);
    const level=Math.max(1,Math.min(3,Number(req.body?.level||1)));
    const inv=(await q(`select i.*,c.company customer_company,c.email from invoices i left join customers c on c.id=i.customer_id where i.id=$1`,[req.params.id]))[0];
    if(!inv)return res.status(404).json({error:"Rechnung nicht gefunden"});
    const paid=(await q(`select coalesce(sum(amount),0) total from invoice_payments where invoice_id=$1`,[inv.id])).total;
    const remaining=Math.max(0,Number(inv.gross)-Number(paid));
    if(remaining<=0)return res.status(400).json({error:"Rechnung ist vollständig bezahlt"});
    const subject=`Zahlungserinnerung Stufe ${level} · ${inv.invoice_number}`;
    const body=`<p>Guten Tag ${inv.customer_company||""},</p><p>zu Rechnung ${inv.invoice_number} besteht ein offener Betrag von <b>${remaining.toFixed(2)} EUR</b>.</p><p>Bitte prüfen Sie den Zahlungseingang bzw. begleichen Sie den offenen Betrag.</p>`;
    const d=(await q(`insert into invoice_dunning(invoice_id,level,recipient,note) values($1,$2,$3,$4) returning *`,[inv.id,level,inv.email||null,body]))[0];
    await audit(req,"V93_DUNNING_CREATED",`${inv.invoice_number} level=${level} remaining=${remaining.toFixed(2)}`);
    res.json({dunning:d,remaining,subject,body})
  }catch(e){res.status(400).json({error:e.message})}
});
app.get("/api/dunning-v93",auth,roles("Admin","Accounting","Dispatcher"),async(req,res)=>{
  try{
    await q(`create table if not exists invoice_dunning(id uuid primary key default gen_random_uuid(),invoice_id uuid not null references invoices(id) on delete cascade,level integer not null default 1,dunning_date date not null default current_date,status text not null default 'Open',recipient text,sent_at timestamptz,note text,created_at timestamptz not null default now())`);
    res.json(await q(`select d.*,i.invoice_number,i.gross,i.due_date,c.company customer_company,c.email from invoice_dunning d join invoices i on i.id=d.invoice_id left join customers c on c.id=i.customer_id order by d.dunning_date desc,d.created_at desc`))
  }catch(e){res.status(500).json({error:e.message})}
});


// V94 dunning email integration
app.post("/api/invoices/:id/send-dunning-v94",auth,roles("Admin","Accounting"),async(req,res)=>{
  try{
    await q(`create table if not exists invoice_dunning(id uuid primary key default gen_random_uuid(),invoice_id uuid not null references invoices(id) on delete cascade,level integer not null default 1,dunning_date date not null default current_date,status text not null default 'Open',recipient text,sent_at timestamptz,note text,created_at timestamptz not null default now())`);
    await q(`alter table email_outbox add column if not exists dunning_id uuid`);
    const inv=(await q(`select i.*,c.company customer_company,c.email from invoices i left join customers c on c.id=i.customer_id where i.id=$1`,[req.params.id]))[0];
    if(!inv)return res.status(404).json({error:"Rechnung nicht gefunden"});
    if(!inv.email)return res.status(400).json({error:"Kunden-E-Mail fehlt"});
    const paid=(await q(`select coalesce(sum(amount),0) total from invoice_payments where invoice_id=$1`,[inv.id])).total;
    const remaining=Math.max(0,Number(inv.gross)-Number(paid));
    if(remaining<=0)return res.status(400).json({error:"Rechnung ist bezahlt"});
    const level=Math.max(1,Math.min(3,Number(req.body?.level||1)));
    const d=(await q(`insert into invoice_dunning(invoice_id,level,recipient,note) values($1,$2,$3,$4) returning *`,[inv.id,level,inv.email,`Offener Betrag: ${remaining.toFixed(2)} EUR`]))[0];
    const subject=`Zahlungserinnerung Stufe ${level} · ${inv.invoice_number}`;
    const body=`<p>Guten Tag ${inv.customer_company||""},</p><p>zu Rechnung <b>${inv.invoice_number}</b> ist noch ein Betrag von <b>${remaining.toFixed(2)} EUR</b> offen.</p><p>Fälligkeitsdatum: ${inv.due_date||"—"}.</p><p>Bitte prüfen Sie den Zahlungseingang bzw. begleichen Sie den offenen Betrag.</p>`;
    const row=(await q(`insert into email_outbox(customer_id,invoice_id,recipient,subject,body_html,status,dunning_id) values($1,$2,$3,$4,$5,'Queued',$6) returning *`,
      [inv.customer_id,inv.id,inv.email,subject,body,d.id]))[0];
    await audit(req,"V94_DUNNING_QUEUED",`${inv.invoice_number} level=${level} outbox=${row.id}`);
    res.json({ok:true,dunning:d,outbox:row,remaining})
  }catch(e){res.status(400).json({error:e.message})}
});


// V95 automatic dunning monitor
let v95DunningRunning=false;
async function v95DunningSweep(){
  if(v95DunningRunning)return; v95DunningRunning=true;
  try{
    await q(`create table if not exists invoice_dunning(id uuid primary key default gen_random_uuid(),invoice_id uuid not null references invoices(id) on delete cascade,level integer not null default 1,dunning_date date not null default current_date,status text not null default 'Open',recipient text,sent_at timestamptz,note text,created_at timestamptz not null default now())`);
    const overdue=await q(`select i.id,i.invoice_number,i.gross,i.due_date,i.customer_id,c.email,c.company,
      coalesce((select sum(p.amount) from invoice_payments p where p.invoice_id=i.id),0) paid_total
      from invoices i left join customers c on c.id=i.customer_id
      where i.status<>'Paid' and i.due_date is not null and i.due_date<current_date`);
    let prepared=0;
    for(const x of overdue){
      const remaining=Number(x.gross)-Number(x.paid_total||0); if(remaining<=0)continue;
      const count=Number((await q(`select count(*)::int n from invoice_dunning where invoice_id=$1`,[x.id]))[0].n||0);
      const level=Math.min(3,count+1);
      const recent=await q(`select id from invoice_dunning where invoice_id=$1 and dunning_date>=current_date-interval '14 days' order by created_at desc limit 1`,[x.id]);
      if(recent.length)continue;
      await q(`insert into invoice_dunning(invoice_id,level,recipient,note) values($1,$2,$3,$4)`,
        [x.id,level,x.email||null,`Automatisch vorbereitet · offen ${remaining.toFixed(2)} EUR`]);
      prepared++;
    }
    return prepared;
  }catch(e){console.error("V95 dunning worker:",e.message);return 0}
  finally{v95DunningRunning=false}
}
setInterval(()=>v95DunningSweep().catch(e=>console.error(e)),3600000);


app.post("/api/dunning-v95/run",auth,roles("Admin","Accounting"),async(req,res)=>{
  try{res.json({prepared:await v95DunningSweep()})}catch(e){res.status(500).json({error:e.message})}
});


// V96 financial dashboard
app.get("/api/reports/finance-v96",auth,roles("Admin","Accounting","Dispatcher"),async(req,res)=>{
  try{
    const from=req.query.from||new Date(new Date().getFullYear(),new Date().getMonth(),1).toISOString().slice(0,10);
    const to=req.query.to||new Date().toISOString().slice(0,10);
    await q(`create table if not exists invoice_payments(id uuid primary key default gen_random_uuid(),invoice_id uuid not null references invoices(id) on delete cascade,payment_date date not null default current_date,amount numeric not null check(amount>0),method text,reference text,note text,created_at timestamptz not null default now())`);
    const [rev,paid,open,overdue,dunning]=await Promise.all([
      q(`select coalesce(sum(gross),0) total,count(*)::int count from invoices where issue_date between $1 and $2`,[from,to]),
      q(`select coalesce(sum(amount),0) total,count(*)::int count from invoice_payments where payment_date between $1 and $2`,[from,to]),
      q(`select coalesce(sum(gross-coalesce((select sum(p.amount) from invoice_payments p where p.invoice_id=i.id),0)),0) total,count(*)::int count from invoices i where i.status<>'Paid'`,[]),
      q(`select coalesce(sum(gross-coalesce((select sum(p.amount) from invoice_payments p where p.invoice_id=i.id),0)),0) total,count(*)::int count from invoices i where i.status<>'Paid' and i.due_date<current_date`,[]),
      q(`select count(*)::int count from invoice_dunning where status in('Open','Sent')`,[])
    ]);
    const monthly=await q(`select to_char(date_trunc('month',issue_date),'YYYY-MM') month,coalesce(sum(gross),0) revenue from invoices where issue_date>=current_date-interval '12 months' group by 1 order by 1`);
    res.json({period:{from,to},revenue:rev[0],payments:paid[0],open:open[0],overdue:overdue[0],dunning:dunning[0],monthly})
  }catch(e){res.status(500).json({error:e.message})}
});


// V97 cost & profit analytics
app.get("/api/reports/profit-v97",auth,roles("Admin","Accounting","Dispatcher"),async(req,res)=>{
  try{
    const from=req.query.from||new Date(new Date().getFullYear(),new Date().getMonth(),1).toISOString().slice(0,10);
    const to=req.query.to||new Date().toISOString().slice(0,10);
    const trips=await q(`select t.id,t.trip_number,t.planning_date,t.price_net,t.route_total_distance_km,v.name vehicle_name,v.plate,
      coalesce((select sum(amount_net) from trip_costs tc where tc.trip_id=t.id),0) trip_costs,
      coalesce((select sum(fc.liters*fc.price_net) from fuel_entries fc where fc.vehicle_id=t.vehicle_id and fc.entry_date between $1 and $2),0) vehicle_fuel
      from trips t left join vehicles v on v.id=t.vehicle_id
      where coalesce(t.planning_date,t.created_at::date) between $1 and $2 order by planning_date desc`,[from,to]);
    const rows=trips.map(x=>{const revenue=Number(x.price_net||0),cost=Number(x.trip_costs||0)+Number(x.vehicle_fuel||0),margin=revenue-cost;return {...x,revenue,cost,margin,margin_pct:revenue?margin/revenue*100:0}})
    const summary=rows.reduce((a,x)=>({revenue:a.revenue+x.revenue,cost:a.cost+x.cost,margin:a.margin+x.margin}),{revenue:0,cost:0,margin:0});
    res.json({from,to,summary,trip_count:rows.length,trips:rows})
  }catch(e){res.status(500).json({error:e.message})}
});


// V98 vehicle cost analytics
app.get("/api/reports/vehicles-v98",auth,roles("Admin","Accounting","Dispatcher"),async(req,res)=>{
  try{
    const from=req.query.from||new Date(new Date().getFullYear(),new Date().getMonth(),1).toISOString().slice(0,10);
    const to=req.query.to||new Date().toISOString().slice(0,10);
    const rows=await q(`select v.id,v.name,v.plate,
      coalesce((select sum(fe.liters) from fuel_entries fe where fe.vehicle_id=v.id and fe.entry_date between $1 and $2),0) liters,
      coalesce((select sum(fe.liters*fe.price_net) from fuel_entries fe where fe.vehicle_id=v.id and fe.entry_date between $1 and $2),0) fuel_cost,
      coalesce((select sum(vc.amount_net) from vehicle_costs vc where vc.vehicle_id=v.id and vc.cost_date between $1 and $2),0) vehicle_cost,
      coalesce((select sum(t.price_net) from trips t where t.vehicle_id=v.id and coalesce(t.planning_date,t.created_at::date) between $1 and $2),0) revenue,
      coalesce((select sum(t.route_total_distance_km) from trips t where t.vehicle_id=v.id and coalesce(t.planning_date,t.created_at::date) between $1 and $2),0) km,
      coalesce((select count(*) from trips t where t.vehicle_id=v.id and coalesce(t.planning_date,t.created_at::date) between $1 and $2),0) trips
      from vehicles v order by v.name`,[from,to]);
    const data=rows.map(x=>{const cost=Number(x.fuel_cost)+Number(x.vehicle_cost),km=Number(x.km||0),fuel=Number(x.liters||0);return {...x,revenue:Number(x.revenue||0),fuel_cost:Number(x.fuel_cost||0),vehicle_cost:Number(x.vehicle_cost||0),total_cost:cost,cost_per_km:km?cost/km:0,liters_per_100km:km?fuel/km*100:0,margin:Number(x.revenue||0)-cost}})
    res.json({from,to,vehicles:data})
  }catch(e){res.status(500).json({error:e.message})}
});


// -- V99 maintenance planning enhancements
// CREATE TABLE IF NOT EXISTS vehicle_maintenance_plans(
// id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
// vehicle_id uuid NOT NULL REFERENCES vehicles(id) ON DELETE CASCADE,
// title text NOT NULL,
// maintenance_type text NOT NULL DEFAULT 'service',
// due_date date,
// due_odometer_km numeric,
// interval_km numeric,
// interval_days integer,
// estimated_cost numeric NOT NULL DEFAULT 0,
// provider text,
// active boolean NOT NULL DEFAULT true,
// note text,
// created_at timestamptz NOT NULL DEFAULT now()
// );
// // // V99 maintenance planning & due alerts
app.get("/api/vehicles/maintenance-v99",auth,roles("Admin","Accounting","Dispatcher"),async(req,res)=>{
  try{
    const rows=await q(`select p.*,v.name vehicle_name,v.plate,v.odometer_km,
      case when p.due_date is not null and p.due_date<=current_date+30 then true else false end date_due,
      case when p.due_odometer_km is not null and v.odometer_km>=p.due_odometer_km then true else false end km_due
      from vehicle_maintenance_plans p join vehicles v on v.id=p.vehicle_id
      where p.active=true order by least(coalesce(p.due_date,'2999-12-31'::date),'2999-12-31'::date),v.name`);
    res.json({items:rows.map(x=>({...x,overdue:!!(x.due_date&&new Date(x.due_date)<new Date())||!!(x.due_odometer_km&&Number(x.odometer_km)>=Number(x.due_odometer_km)),due:!!x.date_due||!!x.km_due}))})
  }catch(e){res.status(500).json({error:e.message})}
});
app.post("/api/vehicles/maintenance-v99",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const {vehicle_id,title,maintenance_type,due_date,due_odometer_km,interval_km,interval_days,estimated_cost,provider,note}=req.body;
    if(!vehicle_id||!title)return res.status(400).json({error:"vehicle_id and title required"});
    const r=await q(`insert into vehicle_maintenance_plans(vehicle_id,title,maintenance_type,due_date,due_odometer_km,interval_km,interval_days,estimated_cost,provider,note) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) returning *`,
      [vehicle_id,title,maintenance_type||"service",due_date||null,due_odometer_km||null,interval_km||null,interval_days||null,estimated_cost||0,provider||null,note||null]);
    await audit(req,"vehicle_maintenance_plan_created",r.rows[0].id); res.json(r.rows[0]);
  }catch(e){res.status(500).json({error:e.message})}
});


// V100 vehicle cockpit
app.get("/api/vehicles/cockpit-v100",auth,roles("Admin","Accounting","Dispatcher"),async(req,res)=>{
  try{
    const vs=await q(`select v.*,coalesce((select sum(fe.liters*fe.price_net) from fuel_entries fe where fe.vehicle_id=v.id),0) fuel_cost_total,
      coalesce((select sum(vc.amount_net) from vehicle_costs vc where vc.vehicle_id=v.id),0) vehicle_cost_total,
      coalesce((select sum(vm.estimated_cost) from vehicle_maintenance_plans vm where vm.vehicle_id=v.id and vm.active),0) planned_maintenance_cost
      from vehicles v order by v.name`);
    const out=[];
    for(const v of vs.rows){
      const maint=await q(`select * from vehicle_maintenance_plans where vehicle_id=$1 and active=true order by due_date nulls last,due_odometer_km nulls last`,[v.id]);
      const dmg=await q(`select * from vehicle_damage where vehicle_id=$1 order by created_at desc limit 10`,[v.id]);
      const costs=await q(`select * from vehicle_costs where vehicle_id=$1 order by cost_date desc limit 10`,[v.id]);
      out.push({...v,maintenance:maint.rows,damages:dmg.rows,cost_history:costs.rows});
    }
    res.json({vehicles:out});
  }catch(e){res.status(500).json({error:e.message})}
});


// -- V101 damage and repair management
// ALTER TABLE vehicle_damage ADD COLUMN IF NOT EXISTS status text NOT NULL DEFAULT 'Open';
// ALTER TABLE vehicle_damage ADD COLUMN IF NOT EXISTS repair_status text NOT NULL DEFAULT 'Not Started';
// ALTER TABLE vehicle_damage ADD COLUMN IF NOT EXISTS repair_start_date date;
// ALTER TABLE vehicle_damage ADD COLUMN IF NOT EXISTS repair_end_date date;
// ALTER TABLE vehicle_damage ADD COLUMN IF NOT EXISTS workshop text;
// ALTER TABLE vehicle_damage ADD COLUMN IF NOT EXISTS repair_cost_net numeric NOT NULL DEFAULT 0;
// ALTER TABLE vehicle_damage ADD COLUMN IF NOT EXISTS downtime_days numeric NOT NULL DEFAULT 0;
// ALTER TABLE vehicle_damage ADD COLUMN IF NOT EXISTS photo_data text;
// ALTER TABLE vehicle_damage ADD COLUMN IF NOT EXISTS note text;
// // // V101 damage & repair management
app.get("/api/vehicles/damages-v101",auth,roles("Admin","Accounting","Dispatcher"),async(req,res)=>{
  try{
    const r=await q(`select d.*,v.name vehicle_name,v.plate from vehicle_damage d join vehicles v on v.id=d.vehicle_id order by coalesce(d.damage_date,d.created_at::date) desc,d.created_at desc`);
    res.json({items:r.rows});
  }catch(e){res.status(500).json({error:e.message})}
});
app.post("/api/vehicles/damages-v101",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const {vehicle_id,damage_date,description,workshop,repair_status,repair_start_date,repair_end_date,repair_cost_net,downtime_days,photo_data,note}=req.body;
    if(!vehicle_id||!description)return res.status(400).json({error:"vehicle_id and description required"});
    const r=await q(`insert into vehicle_damage(vehicle_id,damage_date,description,workshop,repair_status,repair_start_date,repair_end_date,repair_cost_net,downtime_days,photo_data,note,status)
      values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'Open') returning *`,
      [vehicle_id,damage_date||null,description,workshop||null,repair_status||"Not Started",repair_start_date||null,repair_end_date||null,repair_cost_net||0,downtime_days||0,photo_data||null,note||null]);
    await audit(req,"vehicle_damage_created",r.rows[0].id);res.json(r.rows[0]);
  }catch(e){res.status(500).json({error:e.message})}
});
app.patch("/api/vehicles/damages-v101/:id",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const allowed=["status","repair_status","repair_start_date","repair_end_date","workshop","repair_cost_net","downtime_days","note"];
    const sets=[],vals=[]; for(const k of allowed) if(req.body[k]!==undefined){sets.push(`${k}=$${vals.length+1}`);vals.push(req.body[k])}
    if(!sets.length)return res.status(400).json({error:"No changes"});
    vals.push(req.params.id); const r=await q(`update vehicle_damage set ${sets.join(",")} where id=$${vals.length} returning *`,vals);
    if(!r.rows.length)return res.status(404).json({error:"Not found"}); await audit(req,"vehicle_damage_updated",req.params.id);res.json(r.rows[0]);
  }catch(e){res.status(500).json({error:e.message})}
});


// -- V102 vehicle document management
// CREATE TABLE IF NOT EXISTS vehicle_documents(
// id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
// vehicle_id uuid NOT NULL REFERENCES vehicles(id) ON DELETE CASCADE,
// document_type text NOT NULL,
// title text NOT NULL,
// document_number text,
// valid_from date,
// valid_until date,
// provider text,
// file_data text,
// note text,
// status text NOT NULL DEFAULT 'Active',
// created_at timestamptz NOT NULL DEFAULT now()
// );
// CREATE INDEX IF NOT EXISTS idx_vehicle_documents_due ON vehicle_documents(vehicle_id,valid_until);
// // // V102 vehicle documents
app.get("/api/vehicles/documents-v102",auth,roles("Admin","Accounting","Dispatcher"),async(req,res)=>{
  try{
    const r=await q(`select d.*,v.name vehicle_name,v.plate,
      case when d.valid_until is not null and d.valid_until<current_date then 'Expired'
           when d.valid_until is not null and d.valid_until<=current_date+30 then 'Due'
           else d.status end alert_status
      from vehicle_documents d join vehicles v on v.id=d.vehicle_id
      order by d.valid_until nulls last,d.created_at desc`);
    res.json({items:r.rows});
  }catch(e){res.status(500).json({error:e.message})}
});
app.post("/api/vehicles/documents-v102",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const {vehicle_id,document_type,title,document_number,valid_from,valid_until,provider,file_data,note}=req.body;
    if(!vehicle_id||!document_type||!title)return res.status(400).json({error:"vehicle_id, document_type and title required"});
    const r=await q(`insert into vehicle_documents(vehicle_id,document_type,title,document_number,valid_from,valid_until,provider,file_data,note)
      values($1,$2,$3,$4,$5,$6,$7,$8,$9) returning id,vehicle_id,document_type,title,document_number,valid_from,valid_until,provider,note,status,created_at`,
      [vehicle_id,document_type,title,document_number||null,valid_from||null,valid_until||null,provider||null,file_data||null,note||null]);
    await audit(req,"vehicle_document_created",r.rows[0].id);res.json(r.rows[0]);
  }catch(e){res.status(500).json({error:e.message})}
});
app.patch("/api/vehicles/documents-v102/:id",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const allowed=["title","document_number","valid_from","valid_until","provider","note","status"];
    const sets=[],vals=[];for(const k of allowed)if(req.body[k]!==undefined){sets.push(`${k}=$${vals.length+1}`);vals.push(req.body[k])}
    if(!sets.length)return res.status(400).json({error:"No changes"});
    vals.push(req.params.id);const r=await q(`update vehicle_documents set ${sets.join(",")} where id=$${vals.length} returning *`,vals);
    if(!r.rows.length)return res.status(404).json({error:"Not found"});await audit(req,"vehicle_document_updated",req.params.id);res.json(r.rows[0]);
  }catch(e){res.status(500).json({error:e.message})}
});


// -- V103 centralized vehicle/document alerts
// CREATE TABLE IF NOT EXISTS vehicle_document_alerts(
// id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
// vehicle_id uuid NOT NULL REFERENCES vehicles(id) ON DELETE CASCADE,
// document_id uuid REFERENCES vehicle_documents(id) ON DELETE CASCADE,
// alert_type text NOT NULL,
// severity text NOT NULL DEFAULT 'warning',
// message text NOT NULL,
// due_date date,
// acknowledged boolean NOT NULL DEFAULT false,
// created_at timestamptz NOT NULL DEFAULT now(),
// acknowledged_at timestamptz
// );
// CREATE INDEX IF NOT EXISTS idx_vehicle_document_alerts_open ON vehicle_document_alerts(acknowledged,created_at DESC);
async function v103CheckVehicleDocumentAlerts(){
  const docs=await q(`select d.*,v.name vehicle_name,v.plate from vehicle_documents d join vehicles v on v.id=d.vehicle_id where d.status='Active' and d.valid_until is not null`);
  for(const d of docs.rows){
    const days=Math.ceil((new Date(d.valid_until)-new Date())/86400000);
    const due=days<0||days<=30;
    if(!due)continue;
    const type=days<0?'document_expired':'document_due';
    const severity=days<0?'critical':'warning';
    const exists=await q(`select id from vehicle_document_alerts where document_id=$1 and alert_type=$2 and acknowledged=false limit 1`,[d.id,type]);
    if(!exists.rows.length){
      await q(`insert into vehicle_document_alerts(vehicle_id,document_id,alert_type,severity,message,due_date) values($1,$2,$3,$4,$5,$6)`,
        [d.vehicle_id,d.id,type,severity,`${d.title} für ${d.vehicle_name} (${d.plate}) ${days<0?'ist abgelaufen':'ist bald fällig'}.`,d.valid_until]);
    }
  }
}


app.get("/api/vehicles/alerts-v103",auth,roles("Admin","Accounting","Dispatcher"),async(req,res)=>{
  try{
    await v103CheckVehicleDocumentAlerts();
    const r=await q(`select a.*,v.name vehicle_name,v.plate,d.title document_title,d.document_type from vehicle_document_alerts a join vehicles v on v.id=a.vehicle_id left join vehicle_documents d on d.id=a.document_id where a.acknowledged=false order by case when a.severity='critical' then 1 when a.severity='warning' then 2 else 3 end,a.due_date nulls last`);
    res.json({items:r.rows});
  }catch(e){res.status(500).json({error:e.message})}
});
app.post("/api/vehicles/alerts-v103/:id/ack",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const r=await q(`update vehicle_document_alerts set acknowledged=true,acknowledged_at=now() where id=$1 returning *`,[req.params.id]);
    if(!r.rows.length)return res.status(404).json({error:"Not found"});await audit(req,"vehicle_document_alert_ack",req.params.id);res.json(r.rows[0]);
  }catch(e){res.status(500).json({error:e.message})}
});

// V104 unified operations alert center
app.get("/api/control-center/unified-alerts-v104",auth,roles("Admin","Dispatcher","Accounting"),async(req,res)=>{
  try{
    if(typeof v103CheckVehicleDocumentAlerts==="function") await v103CheckVehicleDocumentAlerts();
    const live=await q(`select a.*,t.trip_number,t.driver_id,v.name vehicle_name,v.plate from control_alerts a left join trips t on t.id=a.trip_id left join vehicles v on v.id=t.vehicle_id where a.acknowledged=false order by a.created_at desc limit 200`);
    const vehicle=await q(`select a.*,v.name vehicle_name,v.plate,d.title document_title,d.document_type from vehicle_document_alerts a join vehicles v on v.id=a.vehicle_id left join vehicle_documents d on d.id=a.document_id where a.acknowledged=false order by a.created_at desc limit 200`);
    const maintenance=await q(`select p.id,p.vehicle_id,p.title,p.due_date,p.due_odometer_km,p.estimated_cost,v.name vehicle_name,v.plate,v.odometer_km from vehicle_maintenance_plans p join vehicles v on v.id=p.vehicle_id where p.active=true and ((p.due_date is not null and p.due_date<=current_date+30) or (p.due_odometer_km is not null and v.odometer_km>=p.due_odometer_km)) order by p.due_date nulls last limit 200`);
    const items=[
      ...live.rows.map(x=>({...x,source:"live",title:x.type||"Live Alert",message:x.message})),
      ...vehicle.rows.map(x=>({...x,source:"document",title:x.document_title||"Dokument",message:x.message})),
      ...maintenance.rows.map(x=>({...x,source:"maintenance",severity:(x.due_date&&new Date(x.due_date)<new Date())||Number(x.odometer_km||0)>=Number(x.due_odometer_km||Infinity)?"critical":"warning",title:x.title,message:`Wartung für ${x.vehicle_name} (${x.plate}) ist fällig oder bald fällig.`}))
    ];
    items.sort((a,b)=>new Date(b.created_at||0)-new Date(a.created_at||0));
    res.json({count:items.length,items});
  }catch(e){res.status(500).json({error:e.message})}
});
app.post("/api/control-center/unified-alerts-v104/ack",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const {source,id}=req.body;
    if(source==="live") await q(`update control_alerts set acknowledged=true,acknowledged_at=now() where id=$1`,[id]);
    else if(source==="document") await q(`update vehicle_document_alerts set acknowledged=true,acknowledged_at=now() where id=$1`,[id]);
    else return res.status(400).json({error:"Maintenance alerts are derived and do not need acknowledgement"});
    await audit(req,"unified_alert_ack",`${source}:${id}`);res.json({ok:true});
  }catch(e){res.status(500).json({error:e.message})}
});


// -- V105 unified push notification log
// CREATE TABLE IF NOT EXISTS notification_delivery_log(
// id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
// source text NOT NULL,
// source_id uuid,
// severity text NOT NULL,
// title text NOT NULL,
// message text NOT NULL,
// recipients_count integer NOT NULL DEFAULT 0,
// sent_at timestamptz NOT NULL DEFAULT now()
// );
// CREATE INDEX IF NOT EXISTS idx_notification_delivery_log_time ON notification_delivery_log(sent_at DESC);
async function v105SendUnifiedPush(alert){
  try{
    if(typeof sendWebPushToAdminsAndDispatchers==="function"){
      const n=await sendWebPushToAdminsAndDispatchers(alert.severity,alert.title,alert.message);
      await q(`insert into notification_delivery_log(source,source_id,severity,title,message,recipients_count) values($1,$2,$3,$4,$5,$6)`,
        [alert.source,alert.id||null,alert.severity,alert.title,alert.message,Number(n||0)]);
      return Number(n||0);
    }
  }catch(e){ console.error("V105 push:",e.message); }
  return 0;
}


// V105 real-time push center
app.get("/api/notifications/push-log-v105",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const r=await q(`select * from notification_delivery_log order by sent_at desc limit 100`);
    res.json({items:r.rows});
  }catch(e){res.status(500).json({error:e.message})}
});
app.post("/api/notifications/push-v105/test",auth,roles("Admin"),async(req,res)=>{
  try{
    const severity=req.body.severity==="critical"?"critical":"warning";
    const title="Emergency Delivery Testalarm";
    const message="Web-Push Verbindung für das zentrale Alarmcenter wurde getestet.";
    const count=await v105SendUnifiedPush({source:"test",id:null,severity,title,message});
    await audit(req,"push_test_v105",`${severity}:${count}`);
    res.json({ok:true,recipients_count:count});
  }catch(e){res.status(500).json({error:e.message})}
});


// -- V106 push device management
// ALTER TABLE push_subscriptions ADD COLUMN IF NOT EXISTS user_id uuid REFERENCES users(id) ON DELETE CASCADE;
// ALTER TABLE push_subscriptions ADD COLUMN IF NOT EXISTS device_name text;
// ALTER TABLE push_subscriptions ADD COLUMN IF NOT EXISTS user_agent text;
// ALTER TABLE push_subscriptions ADD COLUMN IF NOT EXISTS last_seen_at timestamptz;
// ALTER TABLE push_subscriptions ADD COLUMN IF NOT EXISTS active boolean NOT NULL DEFAULT true;
// CREATE INDEX IF NOT EXISTS idx_push_subscriptions_user ON push_subscriptions(user_id,active);
// // // -- V107 push cleanup telemetry
// ALTER TABLE push_subscriptions ADD COLUMN IF NOT EXISTS failure_count integer NOT NULL DEFAULT 0;
// ALTER TABLE push_subscriptions ADD COLUMN IF NOT EXISTS last_error text;
// ALTER TABLE push_subscriptions ADD COLUMN IF NOT EXISTS deactivated_at timestamptz;
// CREATE INDEX IF NOT EXISTS idx_push_subscriptions_failures ON push_subscriptions(active,failure_count);
async function v107RecordPushFailure(subscriptionId,errorText){
  await q(`update push_subscriptions set failure_count=failure_count+1,last_error=$2,
    active=case when $1 in (404,410) then false when failure_count+1>=5 then false else active end,
    deactivated_at=case when $1 in (404,410) or failure_count+1>=5 then now() else deactivated_at end
    where id=$3`,[Number(arguments[0]||0),String(errorText||""),subscriptionId]);
}


// V107 push cleanup/admin endpoint
app.get("/api/notifications/push-health-v107",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const r=await q(`select p.id,p.user_id,p.device_name,p.active,p.failure_count,p.last_error,p.last_seen_at,p.deactivated_at,u.name,u.username,u.role
      from push_subscriptions p left join users u on u.id=p.user_id order by p.active desc,p.failure_count desc,p.last_seen_at desc nulls last`);
    res.json({items:r.rows,summary:{
      total:r.rows.length,
      active:r.rows.filter(x=>x.active).length,
      inactive:r.rows.filter(x=>!x.active).length,
      failing:r.rows.filter(x=>Number(x.failure_count)>0).length
    }});
  }catch(e){res.status(500).json({error:e.message})}
});
app.post("/api/notifications/push-health-v107/reactivate/:id",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const r=await q(`update push_subscriptions set active=true,failure_count=0,last_error=null,deactivated_at=null,last_seen_at=now() where id=$1 returning id`,[req.params.id]);
    if(!r.rows.length)return res.status(404).json({error:"Not found"});
    await audit(req,"push_device_reactivated_v107",req.params.id);res.json({ok:true});
  }catch(e){res.status(500).json({error:e.message})}
});


// -- V108 notification preferences
// CREATE TABLE IF NOT EXISTS notification_preferences(
// id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
// user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
// critical_push boolean NOT NULL DEFAULT true,
// warning_push boolean NOT NULL DEFAULT true,
// info_push boolean NOT NULL DEFAULT false,
// gps_push boolean NOT NULL DEFAULT true,
// eta_push boolean NOT NULL DEFAULT true,
// document_push boolean NOT NULL DEFAULT true,
// maintenance_push boolean NOT NULL DEFAULT true,
// updated_at timestamptz NOT NULL DEFAULT now(),
// UNIQUE(user_id)
// );
// // // V109 preference-aware push dispatch
async function v109PushAllowed(userId,kind){
  const r=await q(`select * from notification_preferences where user_id=$1`,[userId]);
  if(!r.rows.length)return true;
  const p=r.rows[0];
  const map={critical:"critical_push",warning:"warning_push",info:"info_push",gps:"gps_push",eta:"eta_push",document:"document_push",maintenance:"maintenance_push"};
  return map[kind] ? p[map[kind]]!==false : true;
}
async function v109SendToPreferred(kind,severity,title,message){
  if(typeof webpush==="undefined") return 0;
  const users=await q(`select u.id from users u where u.active=true and u.role in('Admin','Dispatcher')`);
  let sent=0;
  for(const u of users.rows){
    if(!(await v109PushAllowed(u.id,kind))) continue;
    const subs=await q(`select id,subscription_json from push_subscriptions where user_id=$1 and active=true`,[u.id]);
    for(const sub of subs.rows){
      try{
        await webpush.sendNotification(JSON.parse(sub.subscription_json),JSON.stringify({title,body:message,severity,source:"v109"}));
        await q(`update push_subscriptions set last_seen_at=now(),failure_count=0,last_error=null where id=$1`,[sub.id]);sent++;
      }catch(e){
        const code=Number(e.statusCode||0);
        await q(`update push_subscriptions set failure_count=failure_count+1,last_error=$2,active=case when $1 in(404,410) or failure_count+1>=5 then false else active end,deactivated_at=case when $1 in(404,410) or failure_count+1>=5 then now() else deactivated_at end where id=$3`,
          [code,String(e.message||e),sub.id]);
      }
    }
  }
  return sent;
}


// V109 preference-aware push test
app.post("/api/notifications/push-preferences-v109/test",auth,roles("Admin"),async(req,res)=>{
  try{
    const kind=["critical","warning","info","gps","eta","document","maintenance"].includes(req.body.kind)?req.body.kind:"warning";
    const severity=kind==="critical"?"critical":kind==="info"?"info":"warning";
    const sent=await v109SendToPreferred(kind,severity,"Emergency Delivery Test",`Test für Benachrichtigungsart: ${kind}`);
    await audit(req,"preference_aware_push_test_v109",`${kind}:${sent}`);
    res.json({ok:true,sent});
  }catch(e){res.status(500).json({error:e.message})}
});


// -- V110 notification inbox
// CREATE TABLE IF NOT EXISTS notification_inbox(
// id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
// user_id uuid REFERENCES users(id) ON DELETE CASCADE,
// source text NOT NULL,
// source_id uuid,
// title text NOT NULL,
// message text NOT NULL,
// severity text NOT NULL DEFAULT 'info',
// read_at timestamptz,
// created_at timestamptz NOT NULL DEFAULT now()
// );
// CREATE INDEX IF NOT EXISTS idx_notification_inbox_user ON notification_inbox(user_id,read_at,created_at DESC);
// // // -- V111 automatic inbox event deduplication
// CREATE TABLE IF NOT EXISTS notification_event_links(
// id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
// event_key text UNIQUE NOT NULL,
// source text NOT NULL,
// source_id uuid,
// created_at timestamptz NOT NULL DEFAULT now()
// );
// CREATE INDEX IF NOT EXISTS idx_notification_event_links_created ON notification_event_links(created_at DESC);
// // // V111 automatic event -> inbox bridge
async function v111CreateInboxEvent(eventKey,source,sourceId,title,message,severity="info",rolesList=["Admin","Dispatcher"]){
  try{
    const exists=await q(`select id from notification_event_links where event_key=$1`,[eventKey]);
    if(exists.rows.length)return 0;
    await q(`insert into notification_event_links(event_key,source,source_id) values($1,$2,$3)`,[eventKey,source,sourceId||null]);
    const users=await q(`select id from users where active=true and role=any($1::text[])`,[rolesList]);
    for(const u of users.rows){
      await q(`insert into notification_inbox(user_id,source,source_id,title,message,severity) values($1,$2,$3,$4,$5,$6)`,
        [u.id,source,sourceId||null,title,message,severity]);
    }
    return users.rows.length;
  }catch(e){console.error("V111 inbox bridge:",e.message);return 0}
}
async function v111SweepEvents(){
  const docs=await q(`select d.id,d.vehicle_id,d.title,d.valid_until,v.name vehicle_name,v.plate
    from vehicle_documents d join vehicles v on v.id=d.vehicle_id
    where d.status='Active' and d.valid_until is not null and d.valid_until<=current_date+30`);
  for(const d of docs.rows){
    const days=Math.ceil((new Date(d.valid_until)-new Date())/86400000);
    const sev=days<0?"critical":"warning";
    await v111CreateInboxEvent(`document:${d.id}:${d.valid_until}`,"document",d.id,
      `${days<0?"Dokument abgelaufen":"Dokument bald fällig"}: ${d.title}`,
      `${d.title} für ${d.vehicle_name} (${d.plate}) ${days<0?"ist abgelaufen.":"läuft innerhalb von 30 Tagen ab."}`,
      sev);
  }
  const maint=await q(`select p.id,p.vehicle_id,p.title,p.due_date,p.due_odometer_km,v.name vehicle_name,v.plate,v.odometer_km
    from vehicle_maintenance_plans p join vehicles v on v.id=p.vehicle_id
    where p.active=true and ((p.due_date is not null and p.due_date<=current_date+30) or (p.due_odometer_km is not null and v.odometer_km>=p.due_odometer_km))`);
  for(const m of maint.rows){
    await v111CreateInboxEvent(`maintenance:${m.id}:${m.due_date||m.due_odometer_km}`,"maintenance",m.id,
      `Wartung fällig: ${m.title}`,
      `Wartung für ${m.vehicle_name} (${m.plate}) ist fällig oder bald fällig.`,
      "warning");
  }
  const alerts=await q(`select a.id,a.trip_id,a.type,a.severity,a.message,t.trip_number from control_alerts a left join trips t on t.id=a.trip_id
    where a.acknowledged=false and a.created_at>=now()-interval '10 minutes'`);
  for(const a of alerts.rows){
    await v111CreateInboxEvent(`live:${a.id}`,"live",a.trip_id,
      `Live-Alarm${a.trip_number?" · "+a.trip_number:""}`,
      a.message,a.severity||"warning");
  }
}


// V111 automatic event sweep
app.post("/api/notifications/inbox-v111/sweep",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{await v111SweepEvents();res.json({ok:true})}catch(e){res.status(500).json({error:e.message})}
});


const v111Timer=setInterval(()=>v111SweepEvents().catch(e=>console.error("V111 sweep:",e.message)),60000);
v111Timer.unref?.();


// -- V112 order event tracking
// CREATE TABLE IF NOT EXISTS order_event_links(
// id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
// order_id uuid NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
// event_key text UNIQUE NOT NULL,
// status text,
// created_at timestamptz NOT NULL DEFAULT now()
// );
// CREATE INDEX IF NOT EXISTS idx_order_event_links_order ON order_event_links(order_id,created_at DESC);
// // // V112 automatic order event notifications
async function v112SweepOrders(){
  const r=await q(`select o.id,o.status,o.reference,o.customer_id,c.company
    from orders o left join customers c on c.id=o.customer_id
    where o.status is not null order by o.created_at desc limit 500`);
  for(const o of r.rows){
    const key=`order:${o.id}:status:${o.status}`;
    const exists=await q(`select id from order_event_links where event_key=$1`,[key]);
    if(exists.rows.length)continue;
    await q(`insert into order_event_links(order_id,event_key,status) values($1,$2,$3)`,[o.id,key,o.status]);
    const important=["new","planned","in_transit","delivered","cancelled","New","Planned","In Transit","Delivered","Cancelled"].includes(o.status);
    if(!important)continue;
    const sev=(String(o.status).toLowerCase().includes("cancel"))?"warning":"info";
    const users=await q(`select id from users where active=true and role in('Admin','Dispatcher')`);
    for(const u of users.rows){
      await q(`insert into notification_inbox(user_id,source,source_id,title,message,severity)
        values($1,'order',$2,$3,$4,$5)`,
        [u.id,o.id,`Auftrag ${o.status}`,`Auftrag ${o.reference||o.id}${o.company?" · "+o.company:""} ist jetzt ${o.status}.`,sev]);
    }
  }
}


// V112 order notification sweep
app.post("/api/notifications/orders-v112/sweep",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{await v112SweepOrders();res.json({ok:true})}catch(e){res.status(500).json({error:e.message})}
});


const v112Timer=setInterval(()=>v112SweepOrders().catch(e=>console.error("V112 sweep:",e.message)),60000);
v112Timer.unref?.();


// -- V113 trip event tracking
// CREATE TABLE IF NOT EXISTS trip_event_links(
// id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
// trip_id uuid NOT NULL REFERENCES trips(id) ON DELETE CASCADE,
// event_key text UNIQUE NOT NULL,
// status text,
// created_at timestamptz NOT NULL DEFAULT now()
// );
// CREATE INDEX IF NOT EXISTS idx_trip_event_links_trip ON trip_event_links(trip_id,created_at DESC);
// // // V113 automatic trip/driver event notifications
async function v113SweepTrips(){
  const r=await q(`select t.id,t.trip_number,t.status,t.live_status,t.gps_status,t.driver_id,
    u.name driver_name,v.name vehicle_name,v.plate
    from trips t left join users u on u.id=t.driver_id left join vehicles v on v.id=t.vehicle_id
    where t.status is not null order by t.updated_at desc limit 500`);
  for(const t of r.rows){
    const events=[];
    if(t.status)events.push(["status:"+t.status,t.status,`Tour ${t.status}`,`Tour ${t.trip_number} ist jetzt ${t.status}.`,String(t.status).toLowerCase().includes("deliver")?"info":"info"]);
    if(t.gps_status==="offline")events.push(["gps:offline","offline","GPS offline",`GPS von ${t.driver_name||"Fahrer"} / ${t.trip_number} ist offline.`,"warning"]);
    if(t.gps_status==="stale")events.push(["gps:stale","stale","GPS veraltet",`GPS von ${t.driver_name||"Fahrer"} / ${t.trip_number} ist veraltet.`,"warning"]);
    for(const e of events){
      const key=`trip:${t.id}:${e[0]}`;
      const exists=await q(`select id from trip_event_links where event_key=$1`,[key]);
      if(exists.rows.length)continue;
      await q(`insert into trip_event_links(trip_id,event_key,status) values($1,$2,$3)`,[t.id,key,e[1]]);
      const users=await q(`select id from users where active=true and role in('Admin','Dispatcher')`);
      for(const u of users.rows)await q(`insert into notification_inbox(user_id,source,source_id,title,message,severity) values($1,'trip',$2,$3,$4,$5)`,
        [u.id,t.id,e[2],e[3],e[4]]);
    }
  }
}


// V113 trip notification sweep
app.post("/api/notifications/trips-v113/sweep",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{await v113SweepTrips();res.json({ok:true})}catch(e){res.status(500).json({error:e.message})}
});


const v113Timer=setInterval(()=>v113SweepTrips().catch(e=>console.error("V113 sweep:",e.message)),60000);
v113Timer.unref?.();


// -- V114 stop event tracking
// CREATE TABLE IF NOT EXISTS stop_event_links(
// id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
// stop_id uuid NOT NULL REFERENCES trip_stops(id) ON DELETE CASCADE,
// event_key text UNIQUE NOT NULL,
// status text,
// created_at timestamptz NOT NULL DEFAULT now()
// );
// CREATE INDEX IF NOT EXISTS idx_stop_event_links_stop ON stop_event_links(stop_id,created_at DESC);
// // // V114 automatic stop/proof event notifications
async function v114SweepStops(){
  const r=await q(`select s.id,s.trip_id,s.stop_order,s.address,s.customer_name,s.delivered_at,s.delivered_kg,s.delivered_pieces,
    s.signature_data,s.delivery_photo,s.proof_lat,s.proof_lng,t.trip_number,t.driver_id,u.name driver_name
    from trip_stops s join trips t on t.id=s.trip_id left join users u on u.id=t.driver_id
    where t.status is not null order by s.id desc limit 1000`);
  for(const st of r.rows){
    const events=[];
    if(st.delivered_at)events.push(["delivered",`Stopp abgeschlossen`,`Stopp ${st.stop_order||""} in ${st.address} von Tour ${st.trip_number} wurde abgeschlossen.`,"info"]);
    if(st.delivered_at&&!st.signature_data)events.push(["missing-signature",`Unterschrift fehlt`,`Bei Stopp ${st.stop_order||""} / ${st.trip_number} fehlt die digitale Unterschrift.`,"warning"]);
    if(st.delivered_at&&!st.delivery_photo)events.push(["missing-photo",`Lieferfoto fehlt`,`Bei Stopp ${st.stop_order||""} / ${st.trip_number} fehlt das Lieferfoto.`,"warning"]);
    if(st.delivered_at&&(st.delivered_kg==null||st.delivered_pieces==null))events.push(["missing-quantity",`Liefermengen fehlen`,`Bei Stopp ${st.stop_order||""} / ${st.trip_number} fehlen KG oder Stückzahl.`,"warning"]);
    for(const e of events){
      const key=`stop:${st.id}:${e[0]}`;
      const exists=await q(`select id from stop_event_links where event_key=$1`,[key]);
      if(exists.rows.length)continue;
      await q(`insert into stop_event_links(stop_id,event_key,status) values($1,$2,$3)`,[st.id,key,e[0]]);
      const users=await q(`select id from users where active=true and role in('Admin','Dispatcher')`);
      for(const u of users.rows)await q(`insert into notification_inbox(user_id,source,source_id,title,message,severity) values($1,'stop',$2,$3,$4,$5)`,
        [u.id,st.id,e[1],e[2],e[3]]);
    }
  }
}


// V114 stop notification sweep
app.post("/api/notifications/stops-v114/sweep",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{await v114SweepStops();res.json({ok:true})}catch(e){res.status(500).json({error:e.message})}
});


const v114Timer=setInterval(()=>v114SweepStops().catch(e=>console.error("V114 sweep:",e.message)),60000);
v114Timer.unref?.();


// -- V115 delivery deviation tracking
// ALTER TABLE trip_stops ADD COLUMN IF NOT EXISTS planned_kg numeric;
// ALTER TABLE trip_stops ADD COLUMN IF NOT EXISTS planned_pieces integer;
// ALTER TABLE trip_stops ADD COLUMN IF NOT EXISTS deviation_note text;
// ALTER TABLE trip_stops ADD COLUMN IF NOT EXISTS deviation_acknowledged boolean NOT NULL DEFAULT false;
// // // V115 delivery deviation analysis
app.get("/api/notifications/deviations-v115",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const r=await q(`select s.id,s.trip_id,s.stop_order,s.address,s.customer_name,s.planned_kg,s.delivered_kg,s.planned_pieces,s.delivered_pieces,
      s.time_window_start,s.time_window_end,s.delivered_at,t.trip_number
      from trip_stops s join trips t on t.id=s.trip_id
      where s.delivered_at is not null
      and (
        (s.planned_kg is not null and abs(coalesce(s.delivered_kg,0)-s.planned_kg)>0.01) or
        (s.planned_pieces is not null and coalesce(s.delivered_pieces,0)<>s.planned_pieces) or
        (s.time_window_end is not null and s.delivered_at::time>s.time_window_end) or
        (s.time_window_start is not null and s.delivered_at::time<s.time_window_start)
      )
      order by s.delivered_at desc`);
    res.json({items:r.rows.map(x=>({
      ...x,
      kg_delta:x.planned_kg==null?null:Number(x.delivered_kg||0)-Number(x.planned_kg),
      pieces_delta:x.planned_pieces==null?null:Number(x.delivered_pieces||0)-Number(x.planned_pieces),
      late:x.time_window_end?String(x.delivered_at).slice(11,19)>String(x.time_window_end):false,
      early:x.time_window_start?String(x.delivered_at).slice(11,19)<String(x.time_window_start):false
    }))});
  }catch(e){res.status(500).json({error:e.message})}
});
app.post("/api/notifications/deviations-v115/sweep",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const r=await q(`select s.id,s.trip_id,s.stop_order,s.address,s.planned_kg,s.delivered_kg,s.planned_pieces,s.delivered_pieces,
      s.time_window_start,s.time_window_end,s.delivered_at,t.trip_number
      from trip_stops s join trips t on t.id=s.trip_id where s.delivered_at is not null`);
    let created=0;
    for(const x of r.rows){
      const kg=x.planned_kg!=null&&Math.abs(Number(x.delivered_kg||0)-Number(x.planned_kg))>.01;
      const pc=x.planned_pieces!=null&&Number(x.delivered_pieces||0)!==Number(x.planned_pieces);
      const time=x.time_window_end&&String(x.delivered_at).slice(11,19)>String(x.time_window_end) ||
                 x.time_window_start&&String(x.delivered_at).slice(11,19)<String(x.time_window_start);
      if(!kg&&!pc&&!time)continue;
      const key=`deviation:${x.id}:${String(x.delivered_at)}`;
      const exists=await q(`select id from notification_event_links where event_key=$1`,[key]);
      if(exists.rows.length)continue;
      await q(`insert into notification_event_links(event_key,source,source_id) values($1,'delivery_deviation',$2)`,[key,x.id]);
      const reasons=[];
      if(kg)reasons.push(`KG geplant ${x.planned_kg}, geliefert ${x.delivered_kg}`);
      if(pc)reasons.push(`Stück geplant ${x.planned_pieces}, geliefert ${x.delivered_pieces}`);
      if(time)reasons.push("Zeitfensterabweichung");
      const users=await q(`select id from users where active=true and role in('Admin','Dispatcher')`);
      for(const u of users.rows)await q(`insert into notification_inbox(user_id,source,source_id,title,message,severity) values($1,'delivery_deviation',$2,$3,$4,'warning')`,
        [u.id,x.id,`Zustellabweichung · ${x.trip_number}`,`Stopp ${x.stop_order||""} in ${x.address}: ${reasons.join("; ")}.`]);
      created+=users.rows.length;
    }
    res.json({ok:true,created});
  }catch(e){res.status(500).json({error:e.message})}
});


async function v115SweepDeviations(){
  const r=await q(`select s.id,s.trip_id,s.stop_order,s.address,s.planned_kg,s.delivered_kg,s.planned_pieces,s.delivered_pieces,
    s.time_window_start,s.time_window_end,s.delivered_at,t.trip_number from trip_stops s join trips t on t.id=s.trip_id where s.delivered_at is not null`);
  for(const x of r.rows){
    const kg=x.planned_kg!=null&&Math.abs(Number(x.delivered_kg||0)-Number(x.planned_kg))>.01;
    const pc=x.planned_pieces!=null&&Number(x.delivered_pieces||0)!==Number(x.planned_pieces);
    const time=(x.time_window_end&&String(x.delivered_at).slice(11,19)>String(x.time_window_end))||(x.time_window_start&&String(x.delivered_at).slice(11,19)<String(x.time_window_start));
    if(!kg&&!pc&&!time)continue;
    const key=`deviation:${x.id}:${String(x.delivered_at)}`;const exists=await q(`select id from notification_event_links where event_key=$1`,[key]);if(exists.rows.length)continue;
    await q(`insert into notification_event_links(event_key,source,source_id) values($1,'delivery_deviation',$2)`,[key,x.id]);
    const reasons=[];if(kg)reasons.push(`KG geplant ${x.planned_kg}, geliefert ${x.delivered_kg}`);if(pc)reasons.push(`Stück geplant ${x.planned_pieces}, geliefert ${x.delivered_pieces}`);if(time)reasons.push("Zeitfensterabweichung");
    const users=await q(`select id from users where active=true and role in('Admin','Dispatcher')`);
    for(const u of users.rows)await q(`insert into notification_inbox(user_id,source,source_id,title,message,severity) values($1,'delivery_deviation',$2,$3,$4,'warning')`,[u.id,x.id,`Zustellabweichung · ${x.trip_number}`,`Stopp ${x.stop_order||""} in ${x.address}: ${reasons.join("; ")}.`]);
  }
}

const v115Timer=setInterval(()=>v115SweepDeviations().catch(e=>console.error('V115 sweep:',e.message)),60000);v115Timer.unref?.();

// -- V116 time-window variance
// ALTER TABLE trip_stops ADD COLUMN IF NOT EXISTS planned_arrival_at timestamptz;
// ALTER TABLE trip_stops ADD COLUMN IF NOT EXISTS actual_arrival_at timestamptz;
// ALTER TABLE trip_stops ADD COLUMN IF NOT EXISTS arrival_variance_min integer;
// // // V116 ETA/arrival variance sweep
async function v116SweepArrivalVariance(){
  const r=await q(`select s.id,s.trip_id,s.stop_order,s.address,s.planned_arrival_at,s.actual_arrival_at,s.eta_at,t.trip_number
    from trip_stops s join trips t on t.id=s.trip_id
    where s.actual_arrival_at is not null`);
  for(const x of r.rows){
    const planned=x.planned_arrival_at||x.eta_at;if(!planned)continue;
    const mins=Math.round((new Date(x.actual_arrival_at)-new Date(planned))/60000);
    await q(`update trip_stops set arrival_variance_min=$1 where id=$2`,[mins,x.id]);
    if(Math.abs(mins)<10)continue;
    const key=`arrival-variance:${x.id}:${String(x.actual_arrival_at)}`;
    const exists=await q(`select id from notification_event_links where event_key=$1`,[key]);if(exists.rows.length)continue;
    await q(`insert into notification_event_links(event_key,source,source_id) values($1,'arrival_variance',$2)`,[key,x.id]);
    const users=await q(`select id from users where active=true and role in('Admin','Dispatcher')`);
    const label=mins>0?"Verspätete Ankunft":"Frühe Ankunft";
    for(const u of users.rows)await q(`insert into notification_inbox(user_id,source,source_id,title,message,severity) values($1,'arrival_variance',$2,$3,$4,'warning')`,
      [u.id,x.id,`${label} · ${x.trip_number}`,`Stopp ${x.stop_order||""} in ${x.address}: ${Math.abs(mins)} Minuten ${mins>0?"zu spät":"zu früh"}.`]);
  }
}


// V116 arrival variance endpoints
app.get("/api/planning/arrival-variance-v116",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const r=await q(`select s.*,t.trip_number from trip_stops s join trips t on t.id=s.trip_id where s.arrival_variance_min is not null order by s.actual_arrival_at desc limit 300`);
    res.json({items:r.rows});
  }catch(e){res.status(500).json({error:e.message})}
});
app.post("/api/planning/arrival-variance-v116/sweep",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{await v116SweepArrivalVariance();res.json({ok:true})}catch(e){res.status(500).json({error:e.message})}
});


const v116Timer=setInterval(()=>v116SweepArrivalVariance().catch(e=>console.error("V116 sweep:",e.message)),60000);
v116Timer.unref?.();


// -- V117 delay escalation
// CREATE TABLE IF NOT EXISTS delay_escalation_rules(
// id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
// name text NOT NULL,
// threshold_minutes integer NOT NULL,
// severity text NOT NULL,
// active boolean DEFAULT true
// );
// INSERT INTO delay_escalation_rules(name,threshold_minutes,severity)
// SELECT '10 Minuten',10,'warning' WHERE NOT EXISTS(SELECT 1 FROM delay_escalation_rules WHERE threshold_minutes=10);
// INSERT INTO delay_escalation_rules(name,threshold_minutes,severity)
// SELECT '30 Minuten',30,'critical' WHERE NOT EXISTS(SELECT 1 FROM delay_escalation_rules WHERE threshold_minutes=30);
// INSERT INTO delay_escalation_rules(name,threshold_minutes,severity)
// SELECT '60 Minuten',60,'critical' WHERE NOT EXISTS(SELECT 1 FROM delay_escalation_rules WHERE threshold_minutes=60);
// // // V117 delay escalation sweep
async function v117SweepDelayEscalation(){
  const r=await q(`select s.id,s.trip_id,s.stop_order,s.address,s.arrival_variance_min,s.actual_arrival_at,t.trip_number
    from trip_stops s join trips t on t.id=s.trip_id
    where s.arrival_variance_min is not null and s.arrival_variance_min>=10
    order by s.arrival_variance_min desc`);
  const rules=(await q(`select * from delay_escalation_rules where active=true order by threshold_minutes`)).rows;
  const users=(await q(`select id from users where active=true and role in('Admin','Dispatcher')`)).rows;
  for(const x of r.rows){
    const rule=rules.filter(a=>x.arrival_variance_min>=a.threshold_minutes).at(-1); if(!rule) continue;
    const key=`delay-escalation:${x.id}:${rule.threshold_minutes}:${String(x.actual_arrival_at)}`;
    const exists=await q(`select id from notification_event_links where event_key=$1`,[key]); if(exists.rows.length) continue;
    await q(`insert into notification_event_links(event_key,source,source_id) values($1,'delay_escalation',$2)`,[key,x.id]);
    for(const u of users){
      await q(`insert into notification_inbox(user_id,source,source_id,title,message,severity) values($1,'delay_escalation',$2,$3,$4,$5)`,
        [u.id,x.id,`Verspätungsstufe ${rule.threshold_minutes} Min · ${x.trip_number}`,
         `Stopp ${x.stop_order||""} in ${x.address}: ${x.arrival_variance_min} Minuten verspätet.`,rule.severity]);
    }
  }
}


// V117 escalation endpoints
app.get("/api/notifications/delay-escalation-v117",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const rules=(await q(`select * from delay_escalation_rules order by threshold_minutes`)).rows;
    const items=(await q(`select s.*,t.trip_number from trip_stops s join trips t on t.id=s.trip_id where s.arrival_variance_min>=10 order by s.arrival_variance_min desc limit 300`)).rows;
    res.json({rules,items});
  }catch(e){res.status(500).json({error:e.message})}
});
app.post("/api/notifications/delay-escalation-v117/sweep",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{await v117SweepDelayEscalation();res.json({ok:true})}catch(e){res.status(500).json({error:e.message})}
});


const v117Timer=setInterval(()=>v117SweepDelayEscalation().catch(e=>console.error("V117 sweep:",e.message)),60000);
v117Timer.unref?.();


// -- V118 customer delay communication
// ALTER TABLE trip_stops ADD COLUMN IF NOT EXISTS customer_delay_notified_at timestamptz;
// ALTER TABLE trip_stops ADD COLUMN IF NOT EXISTS customer_delay_notification_status text;
// // // V118 automatic customer delay communication
async function v118SweepCustomerDelayCommunication(){
  const r=await q(`select s.id,s.trip_id,s.stop_order,s.address,s.arrival_variance_min,s.eta_at,s.actual_arrival_at,
      c.id customer_id,c.company,c.email,t.trip_number
    from trip_stops s join trips t on t.id=s.trip_id
    left join customers c on c.id=t.customer_id
    where s.arrival_variance_min>=10 and coalesce(s.customer_delay_notified_at,null) is null
      and c.email is not null and trim(c.email)<>''`);
  for(const x of r.rows){
    const eta=x.eta_at ? new Date(x.eta_at).toLocaleString("it-IT") : "da confermare";
    const subject=`Aggiornamento consegna · ${x.trip_number}`;
    const body=`Gentile ${x.company||"Cliente"},\n\nla consegna relativa al viaggio ${x.trip_number} è in ritardo di circa ${x.arrival_variance_min} minuti.\nNuova ETA prevista: ${eta}.\n\nCi scusiamo per il ritardo e la terremo aggiornata.\n\nEmergency Delivery`;
    try{
      const existing=await q(`select id from email_outbox where trip_id=$1 and subject=$2 and status in('Queued','Sending','Sent') limit 1`,[x.trip_id,subject]);
      if(existing.rows.length){await q(`update trip_stops set customer_delay_notified_at=now(),customer_delay_notification_status='AlreadyQueued' where id=$1`,[x.id]);continue;}
      await q(`insert into email_outbox(customer_id,trip_id,to_email,subject,body,status,attempts) values($1,$2,$3,$4,$5,'Queued',0)`,
        [x.customer_id,x.trip_id,x.email,subject,body]);
      await q(`update trip_stops set customer_delay_notified_at=now(),customer_delay_notification_status='Queued' where id=$1`,[x.id]);
      await q(`insert into audit_log(action,details) values('customer_delay_email_queued',$1)`,[`Trip ${x.trip_number}, stop ${x.id}, ${x.email}`]);
    }catch(e){
      await q(`update trip_stops set customer_delay_notification_status=$1 where id=$2`,[`Error: ${e.message}`.slice(0,500),x.id]);
    }
  }
}


// V118 customer delay communication endpoints
app.get("/api/customer-communication/delays-v118",auth,roles("Admin","Dispatcher","Accounting"),async(req,res)=>{
  try{
    const r=await q(`select s.id,s.trip_id,s.stop_order,s.address,s.arrival_variance_min,s.eta_at,s.customer_delay_notified_at,s.customer_delay_notification_status,t.trip_number,c.company,c.email
      from trip_stops s join trips t on t.id=s.trip_id left join customers c on c.id=t.customer_id
      where s.arrival_variance_min>=10 order by s.actual_arrival_at desc nulls last limit 300`);
    res.json({items:r.rows});
  }catch(e){res.status(500).json({error:e.message})}
});
app.post("/api/customer-communication/delays-v118/sweep",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{await v118SweepCustomerDelayCommunication();res.json({ok:true})}catch(e){res.status(500).json({error:e.message})}
});


const v118Timer=setInterval(()=>v118SweepCustomerDelayCommunication().catch(e=>console.error("V118 sweep:",e.message)),60000);
v118Timer.unref?.();


// -- V119 communication escalation/history
// CREATE TABLE IF NOT EXISTS customer_delay_notifications(
// id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
// stop_id uuid REFERENCES trip_stops(id) ON DELETE CASCADE,
// threshold_minutes integer NOT NULL,
// eta_at timestamptz,
// email text,
// subject text,
// outbox_id uuid,
// created_at timestamptz DEFAULT now()
// );
// CREATE INDEX IF NOT EXISTS idx_customer_delay_notifications_stop ON customer_delay_notifications(stop_id,created_at DESC);
// // // V119 intelligent customer ETA updates
async function v119SweepCustomerEtaUpdates(){
  const r=await q(`select s.id,s.trip_id,s.stop_order,s.address,s.arrival_variance_min,s.eta_at,s.customer_delay_notified_at,
      t.trip_number,c.id customer_id,c.company,c.email
    from trip_stops s join trips t on t.id=s.trip_id
    left join customers c on c.id=t.customer_id
    where s.arrival_variance_min>=10 and c.email is not null and trim(c.email)<>''
    order by s.arrival_variance_min desc`);
  for(const x of r.rows){
    const threshold=x.arrival_variance_min>=60?60:x.arrival_variance_min>=30?30:10;
    const last=await q(`select * from customer_delay_notifications where stop_id=$1 order by created_at desc limit 1`,[x.id]);
    const prev=last.rows[0];
    const etaChanged=prev && x.eta_at && prev.eta_at && Math.abs(new Date(x.eta_at)-new Date(prev.eta_at))>=5*60000;
    if(prev && prev.threshold_minutes===threshold && !etaChanged) continue;
    const eta=x.eta_at?new Date(x.eta_at).toLocaleString("it-IT"):"da confermare";
    const text=threshold>=60
      ? `la consegna ${x.trip_number} presenta un ritardo significativo. Il ritardo stimato è di circa ${x.arrival_variance_min} minuti.`
      : threshold>=30
      ? `la consegna ${x.trip_number} presenta un ritardo di circa ${x.arrival_variance_min} minuti.`
      : `la consegna ${x.trip_number} subirà un ritardo stimato di circa ${x.arrival_variance_min} minuti.`;
    const subject=`Aggiornamento consegna ${threshold} min · ${x.trip_number}`;
    const body=`Gentile ${x.company||"Cliente"},\n\n${text}\nNuova ETA prevista: ${eta}.\n\nLa informeremo in caso di ulteriori variazioni.\n\nEmergency Delivery`;
    try{
      const ob=await q(`insert into email_outbox(customer_id,trip_id,to_email,subject,body,status,attempts) values($1,$2,$3,$4,$5,'Queued',0) returning id`,
        [x.customer_id,x.trip_id,x.email,subject,body]);
      await q(`insert into customer_delay_notifications(stop_id,threshold_minutes,eta_at,email,subject,outbox_id) values($1,$2,$3,$4,$5,$6)`,
        [x.id,threshold,x.eta_at,x.email,subject,ob.rows[0].id]);
      await q(`update trip_stops set customer_delay_notified_at=now(),customer_delay_notification_status=$1 where id=$2`,
        [`Queued:${threshold}`,x.id]);
    }catch(e){
      await q(`update trip_stops set customer_delay_notification_status=$1 where id=$2`,[`Error: ${e.message}`.slice(0,500),x.id]);
    }
  }
}


// V119 ETA communication history
app.get("/api/customer-communication/eta-v119",auth,roles("Admin","Dispatcher","Accounting"),async(req,res)=>{
  try{
    const r=await q(`select n.*,t.trip_number,s.stop_order,s.address,c.company
      from customer_delay_notifications n
      join trip_stops s on s.id=n.stop_id
      join trips t on t.id=s.trip_id
      left join customers c on c.id=t.customer_id
      order by n.created_at desc limit 300`);
    res.json({items:r.rows});
  }catch(e){res.status(500).json({error:e.message})}
});
app.post("/api/customer-communication/eta-v119/sweep",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{await v119SweepCustomerEtaUpdates();res.json({ok:true})}catch(e){res.status(500).json({error:e.message})}
});


const v119Timer=setInterval(()=>v119SweepCustomerEtaUpdates().catch(e=>console.error("V119 sweep:",e.message)),60000);
v119Timer.unref?.();


// -- V120 customer communication channels/preferences
// ALTER TABLE customers ADD COLUMN IF NOT EXISTS preferred_delay_channel text DEFAULT 'email';
// ALTER TABLE customers ADD COLUMN IF NOT EXISTS sms_phone text;
// ALTER TABLE customers ADD COLUMN IF NOT EXISTS whatsapp_phone text;
// CREATE TABLE IF NOT EXISTS customer_communication_outbox(
// id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
// customer_id uuid REFERENCES customers(id) ON DELETE CASCADE,
// trip_id uuid REFERENCES trips(id) ON DELETE SET NULL,
// stop_id uuid REFERENCES trip_stops(id) ON DELETE SET NULL,
// channel text NOT NULL,
// recipient text,
// subject text,
// message text NOT NULL,
// status text DEFAULT 'Queued',
// attempts integer DEFAULT 0,
// last_error text,
// sent_at timestamptz,
// created_at timestamptz DEFAULT now()
// );
// // // V120 channel-aware customer delay communication
async function v120SweepCustomerChannels(){
  const r=await q(`select s.id stop_id,s.trip_id,s.stop_order,s.address,s.arrival_variance_min,s.eta_at,
      t.trip_number,c.id customer_id,c.company,c.email,c.preferred_delay_channel,c.sms_phone,c.whatsapp_phone
    from trip_stops s join trips t on t.id=s.trip_id
    left join customers c on c.id=t.customer_id
    where s.arrival_variance_min>=10`);
  for(const x of r.rows){
    let channel=x.preferred_delay_channel||'email';
    let recipient=channel==='sms'?x.sms_phone:channel==='whatsapp'?x.whatsapp_phone:x.email;
    if(!recipient){channel='email';recipient=x.email}
    if(!recipient) continue;
    const threshold=x.arrival_variance_min>=60?60:x.arrival_variance_min>=30?30:10;
    const last=await q(`select * from customer_communication_outbox where stop_id=$1 and channel=$2 order by created_at desc limit 1`,[x.stop_id,channel]);
    const eta=x.eta_at?new Date(x.eta_at).toLocaleString("it-IT"):"da confermare";
    if(last.rows.length && last.rows[0].status in ['Queued','Sending','Sent']) continue;
    const msg=threshold>=60
      ? `Gentile ${x.company||"Cliente"}, la consegna ${x.trip_number} presenta un ritardo significativo di circa ${x.arrival_variance_min} minuti. Nuova ETA: ${eta}.`
      : threshold>=30
      ? `Gentile ${x.company||"Cliente"}, la consegna ${x.trip_number} è in ritardo di circa ${x.arrival_variance_min} minuti. Nuova ETA: ${eta}.`
      : `Gentile ${x.company||"Cliente"}, la consegna ${x.trip_number} subirà un ritardo stimato di circa ${x.arrival_variance_min} minuti. ETA: ${eta}.`;
    const subject=`Aggiornamento consegna · ${x.trip_number}`;
    try{
      await q(`insert into customer_communication_outbox(customer_id,trip_id,stop_id,channel,recipient,subject,message) values($1,$2,$3,$4,$5,$6,$7)`,
        [x.customer_id,x.trip_id,x.stop_id,channel,recipient,subject,msg]);
      await q(`update trip_stops set customer_delay_notification_status=$1 where id=$2`,[`Queued:${channel}:${threshold}`,x.stop_id]);
    }catch(e){console.error("V120 queue:",e.message)}
  }
}


// V120 customer channel endpoints
app.get("/api/customers/communication-v120",auth,roles("Admin","Dispatcher","Accounting"),async(req,res)=>{
  try{
    const r=await q(`select id,company,email,phone,preferred_delay_channel,sms_phone,whatsapp_phone from customers order by company`);
    res.json({items:r.rows});
  }catch(e){res.status(500).json({error:e.message})}
});
app.patch("/api/customers/:id/communication-v120",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const {preferred_delay_channel,sms_phone,whatsapp_phone}=req.body||{};
    if(!['email','sms','whatsapp'].includes(preferred_delay_channel)) return res.status(400).json({error:"Invalid channel"});
    const r=await q(`update customers set preferred_delay_channel=$1,sms_phone=$2,whatsapp_phone=$3 where id=$4 returning id,company,email,preferred_delay_channel,sms_phone,whatsapp_phone`,
      [preferred_delay_channel,sms_phone||null,whatsapp_phone||null,req.params.id]);
    if(!r.rows.length)return res.status(404).json({error:"Customer not found"});
    res.json(r.rows[0]);
  }catch(e){res.status(500).json({error:e.message})}
});
app.get("/api/customer-communication/channels-v120",auth,roles("Admin","Dispatcher","Accounting"),async(req,res)=>{
  try{const r=await q(`select o.*,c.company from customer_communication_outbox o left join customers c on c.id=o.customer_id order by o.created_at desc limit 300`);res.json({items:r.rows})}
  catch(e){res.status(500).json({error:e.message})}
});
app.post("/api/customer-communication/channels-v120/sweep",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{await v120SweepCustomerChannels();res.json({ok:true})}catch(e){res.status(500).json({error:e.message})}
});


const v120Timer=setInterval(()=>v120SweepCustomerChannels().catch(e=>console.error("V120 sweep:",e.message)),60000);
v120Timer.unref?.();


// -- V121 provider delivery tracking
// ALTER TABLE customer_communication_outbox ADD COLUMN IF NOT EXISTS provider text;
// ALTER TABLE customer_communication_outbox ADD COLUMN IF NOT EXISTS provider_message_id text;
// ALTER TABLE customer_communication_outbox ADD COLUMN IF NOT EXISTS delivered_at timestamptz;
// ALTER TABLE customer_communication_outbox ADD COLUMN IF NOT EXISTS next_attempt_at timestamptz;
// // // V121 provider adapter. Configure a real provider before enabling live SMS/WhatsApp.
function v121ProviderConfig(channel){
  if(channel==="sms"){
    return {name:process.env.SMS_PROVIDER||"none",url:process.env.SMS_PROVIDER_URL,token:process.env.SMS_PROVIDER_TOKEN};
  }
  if(channel==="whatsapp"){
    return {name:process.env.WHATSAPP_PROVIDER||"none",url:process.env.WHATSAPP_PROVIDER_URL,token:process.env.WHATSAPP_PROVIDER_TOKEN};
  }
  return null;
}
async function v121SendOne(row){
  const cfg=v121ProviderConfig(row.channel);
  if(!cfg||cfg.name==="none"||!cfg.url||!cfg.token){
    await q(`update customer_communication_outbox set status='ProviderNotConfigured',last_error=$1,next_attempt_at=null where id=$2`,
      [`No live ${row.channel} provider configured`,row.id]); return;
  }
  try{
    const payload={to:row.recipient,message:row.message,subject:row.subject,channel:row.channel,client_reference:String(row.id)};
    const rr=await fetch(cfg.url,{method:"POST",headers:{"content-type":"application/json","authorization":"Bearer "+cfg.token},body:JSON.stringify(payload)});
    const text=await rr.text();
    if(!rr.ok) throw new Error(`HTTP ${rr.status}: ${text.slice(0,400)}`);
    let data={}; try{data=JSON.parse(text)}catch(_){}
    await q(`update customer_communication_outbox set status='Sent',provider=$1,provider_message_id=$2,sent_at=now(),last_error=null,next_attempt_at=null,attempts=attempts+1 where id=$3`,
      [cfg.name,data.message_id||data.id||null,row.id]);
  }catch(e){
    const attempts=(row.attempts||0)+1;
    const terminal=attempts>=5;
    await q(`update customer_communication_outbox set status=$1,attempts=$2,last_error=$3,next_attempt_at=${terminal?"null":"now()+interval '10 minutes'"} where id=$4`,
      [terminal?"Failed":"Retry",attempts,String(e.message).slice(0,500),row.id]);
  }
}
async function v121CommunicationWorker(){
  const r=await q(`select * from customer_communication_outbox
    where channel in('sms','whatsapp') and status in('Queued','Retry')
      and (next_attempt_at is null or next_attempt_at<=now())
    order by created_at asc limit 25`);
  for(const row of r.rows){
    await q(`update customer_communication_outbox set status='Sending' where id=$1`,[row.id]);
    await v121SendOne(row);
  }
}


// V121 provider endpoints
app.get("/api/customer-communication/providers-v121",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  const sms=v121ProviderConfig("sms"), wa=v121ProviderConfig("whatsapp");
  const r=await q(`select channel,status,count(*)::int count from customer_communication_outbox group by channel,status order by channel,status`);
  res.json({providers:{
    sms:{name:sms?.name||"none",configured:!!(sms?.url&&sms?.token)},
    whatsapp:{name:wa?.name||"none",configured:!!(wa?.url&&wa?.token)}
  },queue:r.rows});
});
app.post("/api/customer-communication/providers-v121/worker",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{await v121CommunicationWorker();res.json({ok:true})}catch(e){res.status(500).json({error:e.message})}
});
app.post("/api/customer-communication/providers-v121/retry/:id",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const r=await q(`update customer_communication_outbox set status='Retry',next_attempt_at=now(),last_error=null where id=$1 returning *`,[req.params.id]);
    if(!r.rows.length)return res.status(404).json({error:"Message not found"});
    res.json({ok:true});
  }catch(e){res.status(500).json({error:e.message})}
});


const v121Timer=setInterval(()=>v121CommunicationWorker().catch(e=>console.error("V121 worker:",e.message)),30000);
v121Timer.unref?.();


// -- V122 provider webhook delivery events
// ALTER TABLE customer_communication_outbox ADD COLUMN IF NOT EXISTS delivered_at timestamptz;
// ALTER TABLE customer_communication_outbox ADD COLUMN IF NOT EXISTS provider_status text;
// ALTER TABLE customer_communication_outbox ADD COLUMN IF NOT EXISTS provider_updated_at timestamptz;
// CREATE TABLE IF NOT EXISTS communication_delivery_events(
// id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
// outbox_id uuid REFERENCES customer_communication_outbox(id) ON DELETE SET NULL,
// provider text,
// provider_message_id text,
// event_status text NOT NULL,
// event_payload text,
// created_at timestamptz DEFAULT now()
// );
// CREATE INDEX IF NOT EXISTS idx_comm_delivery_events_outbox ON communication_delivery_events(outbox_id,created_at DESC);
// // // V122 provider webhook normalization
function v122NormalizeStatus(v){
  const x=String(v||"").toLowerCase();
  if(["delivered","delivery","deliv"].includes(x)) return "delivered";
  if(["sent","accepted","queued","submitted"].includes(x)) return x==="sent"?"sent":"sent";
  if(["failed","failure","undelivered","rejected","error"].includes(x)) return "failed";
  if(["read","seen"].includes(x)) return "read";
  return "unknown";
}
async function v122ApplyWebhook(body){
  const provider=body.provider||body.source||"unknown";
  const messageId=body.message_id||body.messageId||body.sid||body.id;
  const status=v122NormalizeStatus(body.status||body.event||body.type);
  if(!messageId) throw new Error("provider_message_id missing");
  const r=await q(`select id from customer_communication_outbox where provider_message_id=$1 limit 1`,[messageId]);
  const outboxId=r.rows[0]?.id||null;
  await q(`insert into communication_delivery_events(outbox_id,provider,provider_message_id,event_status,event_payload) values($1,$2,$3,$4,$5)`,
    [outboxId,provider,messageId,status,JSON.stringify(body).slice(0,10000)]);
  if(outboxId){
    const map={delivered:"Delivered",read:"Read",failed:"Failed",sent:"Sent"};
    const newStatus=map[status];
    if(newStatus){
      await q(`update customer_communication_outbox set provider_status=$1,provider_updated_at=now(),status=$2,delivered_at=${status==="delivered"?"now()":"delivered_at"} where id=$3`,
        [status,newStatus,outboxId]);
    }
  }
  return {ok:true,outbox_id:outboxId,status};
}


// V122 public webhook endpoints

// V123 secure webhook endpoint. Expects X-Webhook-Signature: sha256=<HMAC-SHA256>.
app.post("/api/webhooks/communication-v123/:provider",async(req,res)=>{
  const provider=req.params.provider;
  const ip=req.ip||req.headers["x-forwarded-for"]||"unknown";
  try{
    if(!(await v123CheckRate(provider,ip))){
      await q(`insert into communication_webhook_security_log(provider,accepted,reason,remote_ip) values($1,false,'rate_limited',$2)`,[provider,ip]);
      return res.status(429).json({error:"Rate limit exceeded"});
    }
    const secret=v123Secret(provider);
    if(!secret){
      await q(`insert into communication_webhook_security_log(provider,accepted,reason,remote_ip) values($1,false,'secret_not_configured',$2)`,[provider,ip]);
      return res.status(503).json({error:"Webhook secret not configured"});
    }
    const raw=JSON.stringify(req.body||{});
    const signature=req.headers["x-webhook-signature"]||req.headers["x-signature"];
    if(!v123VerifySignature(raw,signature,secret)){
      await q(`insert into communication_webhook_security_log(provider,accepted,reason,remote_ip) values($1,false,'invalid_signature',$2)`,[provider,ip]);
      return res.status(401).json({error:"Invalid webhook signature"});
    }
    const body=req.body||{}; body.provider=provider;
    const result=await v122ApplyWebhook(body);
    await q(`insert into communication_webhook_security_log(provider,accepted,reason,remote_ip) values($1,true,'accepted',$2)`,[provider,ip]);
    res.json(result);
  }catch(e){res.status(400).json({error:e.message})}
});
app.get("/api/customer-communication/webhook-security-v123",auth,roles("Admin"),async(req,res)=>{
  try{
    const r=await q(`select provider,accepted,reason,remote_ip,created_at from communication_webhook_security_log order by created_at desc limit 300`);
    res.json({items:r.rows});
  }catch(e){res.status(500).json({error:e.message})}
});

app.post("/api/webhooks/communication-v122/:provider",async(req,res)=>{
  try{
    const body=req.body||{}; body.provider=req.params.provider;
    const result=await v122ApplyWebhook(body); res.json(result);
  }catch(e){res.status(400).json({error:e.message})}
});
app.get("/api/customer-communication/delivery-events-v122",auth,roles("Admin","Dispatcher","Accounting"),async(req,res)=>{
  try{
    const r=await q(`select e.*,o.channel,o.recipient,o.subject,c.company
      from communication_delivery_events e
      left join customer_communication_outbox o on o.id=e.outbox_id
      left join customers c on c.id=o.customer_id
      order by e.created_at desc limit 500`);
    res.json({items:r.rows});
  }catch(e){res.status(500).json({error:e.message})}
});


// -- V123 webhook security
// CREATE TABLE IF NOT EXISTS communication_webhook_secrets(
// provider text PRIMARY KEY,
// secret text NOT NULL,
// active boolean DEFAULT true,
// updated_at timestamptz DEFAULT now()
// );
// CREATE TABLE IF NOT EXISTS communication_webhook_security_log(
// id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
// provider text,
// accepted boolean NOT NULL,
// reason text,
// remote_ip text,
// created_at timestamptz DEFAULT now()
// );
// // // V123 signed webhook verification
const crypto = require("crypto");
function v123Secret(provider){
  const envKey=String(provider||"").toUpperCase().replace(/[^A-Z0-9]/g,"_")+"_WEBHOOK_SECRET";
  return process.env[envKey]||null;
}
function v123VerifySignature(raw, signature, secret){
  if(!secret||!signature) return false;
  const sig=String(signature).replace(/^sha256=/i,"");
  const expected=crypto.createHmac("sha256",secret).update(raw).digest("hex");
  try{return crypto.timingSafeEqual(Buffer.from(sig,"hex"),Buffer.from(expected,"hex"))}catch(e){return false}
}
async function v123CheckRate(provider,ip){
  const r=await q(`select count(*)::int count from communication_webhook_security_log where provider=$1 and remote_ip=$2 and accepted=false and created_at>now()-interval '10 minutes'`,[provider,ip]);
  return r.rows[0].count<30;
}


// -- V124 communication templates and customer language
// ALTER TABLE customers ADD COLUMN IF NOT EXISTS communication_language text DEFAULT 'it';
// CREATE TABLE IF NOT EXISTS communication_templates(
// id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
// channel text NOT NULL,
// language text NOT NULL DEFAULT 'it',
// event_type text NOT NULL,
// threshold_minutes integer DEFAULT 0,
// subject text,
// body text NOT NULL,
// active boolean DEFAULT true,
// updated_at timestamptz DEFAULT now()
// );
// CREATE UNIQUE INDEX IF NOT EXISTS uq_comm_template ON communication_templates(channel,language,event_type,threshold_minutes);
// INSERT INTO communication_templates(channel,language,event_type,threshold_minutes,subject,body)
// SELECT 'email','it','delay',10,'Aggiornamento consegna {{trip_number}}','Gentile {{customer}}, la consegna {{trip_number}} presenta un ritardo di circa {{delay_minutes}} minuti. Nuova ETA: {{eta}}. Cordiali saluti, Emergency Delivery.'
// WHERE NOT EXISTS(SELECT 1 FROM communication_templates WHERE channel='email' AND language='it' AND event_type='delay' AND threshold_minutes=10);
// INSERT INTO communication_templates(channel,language,event_type,threshold_minutes,subject,body)
// SELECT 'email','it','delay',30,'Ritardo consegna {{trip_number}}','Gentile {{customer}}, la consegna {{trip_number}} è attualmente in ritardo di circa {{delay_minutes}} minuti. Nuova ETA: {{eta}}. Cordiali saluti, Emergency Delivery.'
// WHERE NOT EXISTS(SELECT 1 FROM communication_templates WHERE channel='email' AND language='it' AND event_type='delay' AND threshold_minutes=30);
// INSERT INTO communication_templates(channel,language,event_type,threshold_minutes,subject,body)
// SELECT 'email','en','delay',10,'Delivery update {{trip_number}}','Dear {{customer}}, delivery {{trip_number}} is currently delayed by about {{delay_minutes}} minutes. New ETA: {{eta}}. Regards, Emergency Delivery.'
// WHERE NOT EXISTS(SELECT 1 FROM communication_templates WHERE channel='email' AND language='en' AND event_type='delay' AND threshold_minutes=10);
// INSERT INTO communication_templates(channel,language,event_type,threshold_minutes,subject,body)
// SELECT 'email','de','delay',10,'Lieferupdate {{trip_number}}','Guten Tag {{customer}}, die Lieferung {{trip_number}} verspätet sich voraussichtlich um etwa {{delay_minutes}} Minuten. Neue ETA: {{eta}}. Viele Grüße, Emergency Delivery.'
// WHERE NOT EXISTS(SELECT 1 FROM communication_templates WHERE channel='email' AND language='de' AND event_type='delay' AND threshold_minutes=10);
// // // V124 template rendering
function v124Render(t,data){
  return String(t||"").replace(/\{\{\s*(\w+)\s*\}\}/g,(_,k)=>data[k]??"");
}
async function v124Template(channel,language,eventType,threshold){
  let r=await q(`select * from communication_templates where active=true and channel=$1 and language=$2 and event_type=$3 and threshold_minutes<=$4 order by threshold_minutes desc limit 1`,
    [channel,language,eventType,threshold]);
  if(!r.rows.length && language!=="it") r=await q(`select * from communication_templates where active=true and channel=$1 and language='it' and event_type=$2 and threshold_minutes<=$3 order by threshold_minutes desc limit 1`,
    [channel,eventType,threshold]);
  return r.rows[0]||null;
}


// V124 template/customer-language endpoints
app.get("/api/customer-communication/templates-v124",auth,roles("Admin","Dispatcher","Accounting"),async(req,res)=>{
  try{const r=await q(`select * from communication_templates order by channel,language,event_type,threshold_minutes`);res.json({items:r.rows})}
  catch(e){res.status(500).json({error:e.message})}
});
app.post("/api/customer-communication/templates-v124",auth,roles("Admin"),async(req,res)=>{
  try{
    const {channel,language,event_type,threshold_minutes,subject,body,active=true}=req.body||{};
    if(!['email','sms','whatsapp'].includes(channel))return res.status(400).json({error:"Invalid channel"});
    const r=await q(`insert into communication_templates(channel,language,event_type,threshold_minutes,subject,body,active) values($1,$2,$3,$4,$5,$6,$7) returning *`,
      [channel,language||'it',event_type||'delay',Number(threshold_minutes)||0,subject||'',body||'',active]);
    res.json(r.rows[0]);
  }catch(e){res.status(500).json({error:e.message})}
});
app.patch("/api/customers/:id/communication-language-v124",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const lang=String(req.body?.language||'it').toLowerCase();
    if(!['it','de','en'].includes(lang))return res.status(400).json({error:"Unsupported language"});
    const r=await q(`update customers set communication_language=$1 where id=$2 returning id,company,communication_language`,[lang,req.params.id]);
    if(!r.rows.length)return res.status(404).json({error:"Customer not found"});
    res.json(r.rows[0]);
  }catch(e){res.status(500).json({error:e.message})}
});


// V125 communication template editor/test
app.patch("/api/customer-communication/templates-v125/:id",auth,roles("Admin"),async(req,res)=>{
  try{
    const {subject,body,active,threshold_minutes,language,channel,event_type}=req.body||{};
    const r=await q(`update communication_templates set subject=coalesce($1,subject),body=coalesce($2,body),active=coalesce($3,active),
      threshold_minutes=coalesce($4,threshold_minutes),language=coalesce($5,language),channel=coalesce($6,channel),
      event_type=coalesce($7,event_type),updated_at=now() where id=$8 returning *`,
      [subject,body,active===undefined?null:!!active,threshold_minutes===undefined?null:Number(threshold_minutes),language,channel,event_type,req.params.id]);
    if(!r.rows.length)return res.status(404).json({error:"Template not found"});
    res.json(r.rows[0]);
  }catch(e){res.status(500).json({error:e.message})}
});
app.post("/api/customer-communication/templates-v125/preview",auth,roles("Admin","Dispatcher","Accounting"),async(req,res)=>{
  try{
    const {template_id,data={}}=req.body||{};
    const r=await q(`select * from communication_templates where id=$1`,[template_id]);
    if(!r.rows.length)return res.status(404).json({error:"Template not found"});
    const t=r.rows[0];
    res.json({subject:v124Render(t.subject,data),body:v124Render(t.body,data),template:t});
  }catch(e){res.status(500).json({error:e.message})}
});
app.post("/api/customer-communication/templates-v125/test",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const {template_id,recipient,data={}}=req.body||{};
    const r=await q(`select * from communication_templates where id=$1`,[template_id]);
    if(!r.rows.length)return res.status(404).json({error:"Template not found"});
    const t=r.rows[0];
    if(!recipient)return res.status(400).json({error:"Recipient required"});
    const subject=v124Render(t.subject,data), body=v124Render(t.body,data);
    if(t.channel==="email"){
      await q(`insert into email_outbox(to_email,subject,body,status,attempts) values($1,$2,$3,'Queued',0)`,[recipient,subject,body]);
    }else{
      await q(`insert into customer_communication_outbox(channel,recipient,subject,message,status,attempts) values($1,$2,$3,$4,'Queued',0)`,[t.channel,recipient,subject,body]);
    }
    res.json({ok:true,queued:true,channel:t.channel,recipient,subject,body});
  }catch(e){res.status(500).json({error:e.message})}
});


// V126 unified communication workflow
async function v126ProcessDelayCommunications(){
  const r=await q(`select s.id stop_id,s.trip_id,s.stop_order,s.address,s.arrival_variance_min,s.eta_at,
      t.trip_number,c.id customer_id,c.company,c.email,c.communication_language,c.preferred_delay_channel,c.sms_phone,c.whatsapp_phone
    from trip_stops s join trips t on t.id=s.trip_id left join customers c on c.id=t.customer_id
    where s.arrival_variance_min>=10`);
  for(const x of r.rows){
    let channel=x.preferred_delay_channel||"email";
    let recipient=channel==="sms"?x.sms_phone:channel==="whatsapp"?x.whatsapp_phone:x.email;
    if(!recipient){channel="email";recipient=x.email}
    if(!recipient) continue;
    const threshold=x.arrival_variance_min>=60?60:x.arrival_variance_min>=30?30:10;
    const tpl=await v124Template(channel,x.communication_language||"it","delay",threshold);
    if(!tpl) continue;
    const eta=x.eta_at?new Date(x.eta_at).toLocaleString("it-IT"):"da confermare";
    const data={customer:x.company||"Cliente",trip_number:x.trip_number,delay_minutes:x.arrival_variance_min,eta};
    const subject=v124Render(tpl.subject,data), body=v124Render(tpl.body,data);
    const prev=await q(`select id,status,provider_status from customer_communication_outbox where stop_id=$1 and channel=$2 order by created_at desc limit 1`,[x.stop_id,channel]);
    if(prev.rows.length && ["Queued","Sending","Sent","Delivered","Read"].includes(prev.rows[0].status)) continue;
    if(channel==="email"){
      const e=await q(`insert into email_outbox(customer_id,trip_id,to_email,subject,body,status,attempts) values($1,$2,$3,$4,$5,'Queued',0) returning id`,
        [x.customer_id,x.trip_id,recipient,subject,body]);
      await q(`insert into customer_communication_outbox(customer_id,trip_id,stop_id,channel,recipient,subject,message,status,attempts) values($1,$2,$3,'email',$4,$5,$6,'Queued',0)`,
        [x.customer_id,x.trip_id,x.stop_id,recipient,subject,body]);
    }else{
      await q(`insert into customer_communication_outbox(customer_id,trip_id,stop_id,channel,recipient,subject,message,status,attempts) values($1,$2,$3,$4,$5,$6,$7,'Queued',0)`,
        [x.customer_id,x.trip_id,x.stop_id,channel,recipient,subject,body]);
    }
    await q(`update trip_stops set customer_delay_notification_status=$1,customer_delay_notified_at=now() where id=$2`,
      [`WorkflowQueued:${channel}:${threshold}`,x.stop_id]);
  }
}


// V126 unified communication workflow endpoints
app.get("/api/customer-communication/workflow-v126",auth,roles("Admin","Dispatcher","Accounting"),async(req,res)=>{
  try{
    const r=await q(`select o.*,c.company,t.trip_number,s.stop_order
      from customer_communication_outbox o
      left join customers c on c.id=o.customer_id
      left join trips t on t.id=o.trip_id
      left join trip_stops s on s.id=o.stop_id
      order by o.created_at desc limit 500`);
    res.json({items:r.rows});
  }catch(e){res.status(500).json({error:e.message})}
});
app.post("/api/customer-communication/workflow-v126/run",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{await v126ProcessDelayCommunications();res.json({ok:true})}catch(e){res.status(500).json({error:e.message})}
});


const v126Timer=setInterval(()=>v126ProcessDelayCommunications().catch(e=>console.error("V126 workflow:",e.message)),60000);
v126Timer.unref?.();


// V127 customer portal
async function v127EnsurePortal(){
 await q(`create table if not exists customer_portal_tokens(
   id uuid primary key default gen_random_uuid(),customer_id uuid references customers(id) on delete cascade,
   token text unique not null,active boolean default true,expires_at timestamptz,created_at timestamptz default now())`);
 await q(`create index if not exists idx_portal_tokens_token on customer_portal_tokens(token)`);
}
async function v127PortalAuth(req,res,next){
 try{
  const token=(req.headers.authorization||"").replace("Bearer ","")||req.query.token;
  if(!token) return res.status(401).json({error:"Portal token required"});
  const r=await q(`select pt.*,c.company,c.email,c.phone,c.communication_language
    from customer_portal_tokens pt join customers c on c.id=pt.customer_id
    where pt.token=$1 and pt.active=true and (pt.expires_at is null or pt.expires_at>now())`,[token]);
  if(!r.rows.length) return res.status(401).json({error:"Invalid portal token"});
  req.portal=r.rows[0]; next();
 }catch(e){res.status(500).json({error:e.message})}
}


app.post("/api/customer-portal-v127/token",auth,roles("Admin","Dispatcher"),async(req,res)=>{
 try{
  const customerId=req.body.customer_id;
  const token=require("crypto").randomBytes(24).toString("hex");
  const days=Math.max(1,Math.min(365,Number(req.body.days||30)));
  const r=await q(`insert into customer_portal_tokens(customer_id,token,expires_at) values($1,$2,now()+($3||' days')::interval) returning id,token,expires_at`,[customerId,token,String(days)]);
  res.json(r.rows[0]);
 }catch(e){res.status(500).json({error:e.message})}
});
app.get("/api/customer-portal-v127/overview",v127PortalAuth,async(req,res)=>{
 try{
  const cid=req.portal.customer_id;
  const trips=await q(`select t.id,t.trip_number,t.status,t.route,t.price_net,t.created_at,
      v.name vehicle_name,u.name driver_name,
      coalesce(json_agg(json_build_object(
        'id',s.id,'order',s.stop_order,'address',s.address,'customer_name',s.customer_name,
        'planned_time',s.planned_time,'planned_arrival_at',s.planned_arrival_at,
        'actual_arrival_at',s.actual_arrival_at,'arrival_variance_min',s.arrival_variance_min,
        'delivered_at',s.delivered_at,'deviation_note',s.deviation_note,
        'delay_status',s.customer_delay_notification_status
      ) order by s.stop_order) filter(where s.id is not null),'[]') stops
    from trips t left join vehicles v on v.id=t.vehicle_id left join users u on u.id=t.driver_id
    left join trip_stops s on s.trip_id=t.id
    where t.customer_id=$1 group by t.id,v.name,u.name order by t.created_at desc limit 100`,[cid]);
  const invoices=await q(`select invoice_number,issue_date,due_date,net,vat,gross,status,trip_id from invoices where customer_id=$1 order by issue_date desc limit 100`,[cid]);
  const comm=await q(`select o.created_at,o.channel,o.recipient,o.subject,o.status,o.provider_status,o.delivered_at,t.trip_number
    from customer_communication_outbox o left join trips t on t.id=o.trip_id
    where o.customer_id=$1 order by o.created_at desc limit 100`,[cid]);
  res.json({customer:{id:cid,company:req.portal.company,email:req.portal.email,phone:req.portal.phone,language:req.portal.communication_language},
    trips:trips.rows,invoices:invoices.rows,communications:comm.rows});
 }catch(e){res.status(500).json({error:e.message})}
});
app.get("/api/customer-portal-v127/trip/:id",v127PortalAuth,async(req,res)=>{
 try{
  const r=await q(`select t.*,v.name vehicle_name,u.name driver_name,
    coalesce(json_agg(json_build_object('id',s.id,'order',s.stop_order,'address',s.address,'planned_time',s.planned_time,
    'planned_arrival_at',s.planned_arrival_at,'actual_arrival_at',s.actual_arrival_at,'arrival_variance_min',s.arrival_variance_min,
    'delivered_at',s.delivered_at,'deviation_note',s.deviation_note,'delay_status',s.customer_delay_notification_status)
    order by s.stop_order) filter(where s.id is not null),'[]') stops
    from trips t left join vehicles v on v.id=t.vehicle_id left join users u on u.id=t.driver_id left join trip_stops s on s.trip_id=t.id
    where t.id=$1 and t.customer_id=$2 group by t.id,v.name,u.name`,[req.params.id,req.portal.customer_id]);
  if(!r.rows.length) return res.status(404).json({error:"Trip not found"});
  const docs=await q(`select invoice_number,issue_date,due_date,net,vat,gross,status from invoices where trip_id=$1 and customer_id=$2`,[req.params.id,req.portal.customer_id]);
  res.json({trip:r.rows[0],invoices:docs.rows});
 }catch(e){res.status(500).json({error:e.message})}
});

v127EnsurePortal().catch(e=>console.error('V127 portal schema:',e.message));

// V128 customer-facing portal and tracking
app.get("/customer-portal",async(req,res)=>{
  res.sendFile(require("path").join(__dirname,"public","customer-portal.html"));
});
app.get("/track/:token",async(req,res)=>{
  res.sendFile(require("path").join(__dirname,"public","tracking.html"));
});
app.post("/api/customer-portal-v128/login",async(req,res)=>{
  try{
    const token=String(req.body.token||"").trim();
    const r=await q(`select pt.token,pt.expires_at,c.company from customer_portal_tokens pt
      join customers c on c.id=pt.customer_id where pt.token=$1 and pt.active=true
      and (pt.expires_at is null or pt.expires_at>now())`,[token]);
    if(!r.rows.length) return res.status(401).json({error:"Ungültiger oder abgelaufener Portalzugang"});
    res.json({token:r.rows[0].token,company:r.rows[0].company,expires_at:r.rows[0].expires_at});
  }catch(e){res.status(500).json({error:e.message})}
});
app.get("/api/customer-portal-v128/document/:invoiceNumber",v127PortalAuth,async(req,res)=>{
  try{
    const r=await q(`select * from invoices where invoice_number=$1 and customer_id=$2`,[req.params.invoiceNumber,req.portal.customer_id]);
    if(!r.rows.length) return res.status(404).json({error:"Dokument nicht gefunden"});
    const i=r.rows[0];
    res.json({invoice:i,download_url:`/api/invoices/${i.id}/pdf`});
  }catch(e){res.status(500).json({error:e.message})}
});
app.get("/api/tracking-v128/:token",async(req,res)=>{
  try{
    const r=await q(`select t.id,t.trip_number,t.status,t.route,t.current_lat,t.current_lng,t.updated_at,
      c.company,t.price_net,
      coalesce(json_agg(json_build_object('order',s.stop_order,'address',s.address,'planned_time',s.planned_time,
      'planned_arrival_at',s.planned_arrival_at,'actual_arrival_at',s.actual_arrival_at,
      'arrival_variance_min',s.arrival_variance_min,'delivered_at',s.delivered_at)
      order by s.stop_order) filter(where s.id is not null),'[]') stops
      from trips t join customers c on c.id=t.customer_id
      left join trip_stops s on s.trip_id=t.id
      where t.id=$1 group by t.id,c.company`,[req.params.token]);
    if(!r.rows.length) return res.status(404).json({error:"Tracking nicht gefunden"});
    const x=r.rows[0]; res.json({trip_number:x.trip_number,status:x.status,company:x.company,
      route:x.route,current_lat:x.current_lat,current_lng:x.current_lng,updated_at:x.updated_at,stops:x.stops});
  }catch(e){res.status(500).json({error:e.message})}
});


// V129 customer document center and delivery notifications
app.get("/api/customer-portal-v129/documents",v127PortalAuth,async(req,res)=>{
 try{
  const cid=req.portal.customer_id;
  const inv=await q(`select id,invoice_number,issue_date,due_date,net,vat,gross,status,trip_id from invoices where customer_id=$1 order by issue_date desc`,[cid]);
  const trips=await q(`select t.id,t.trip_number,t.status,t.customer_id,
    s.delivered_at,s.signature_data,s.delivery_photo,s.deviation_note
    from trips t join trip_stops s on s.trip_id=t.id where t.customer_id=$1 and s.delivered_at is not null
    order by s.delivered_at desc`,[cid]);
  res.json({invoices:inv.rows,deliveries:trips.rows});
 }catch(e){res.status(500).json({error:e.message})}
});
app.get("/api/customer-portal-v129/invoice/:id",v127PortalAuth,async(req,res)=>{
 try{
  const r=await q(`select * from invoices where id=$1 and customer_id=$2`,[req.params.id,req.portal.customer_id]);
  if(!r.rows.length)return res.status(404).json({error:"Rechnung nicht gefunden"});
  res.json({invoice:r.rows[0]});
 }catch(e){res.status(500).json({error:e.message})}
});
app.post("/api/customer-portal-v129/document-notification-sweep",auth,roles("Admin","Dispatcher"),async(req,res)=>{
 try{
  const r=await q(`select t.id,t.trip_number,c.id customer_id,c.email,s.id stop_id,s.delivered_at
    from trip_stops s join trips t on t.id=s.trip_id join customers c on c.id=t.customer_id
    where s.delivered_at is not null and c.email is not null
    and not exists(select 1 from customer_communication_outbox o where o.stop_id=s.id and o.subject like 'Delivery documents%')`);
  let queued=0;
  for(const x of r.rows){
    const body=`Dear customer,\n\nDelivery ${x.trip_number} was completed successfully. Your delivery documents are available in the customer portal.\n\nEmergency Delivery`;
    await q(`insert into customer_communication_outbox(customer_id,trip_id,stop_id,channel,recipient,subject,message,status,attempts)
      values($1,$2,$3,'email',$4,'Delivery documents available',$5,'Queued',0)`,
      [x.customer_id,x.id,x.stop_id,x.email,body]);
    queued++;
  }
  res.json({ok:true,queued});
 }catch(e){res.status(500).json({error:e.message})}
});


// V130 digital delivery proof center
app.get("/api/customer-portal-v130/delivery-proof/:tripId",v127PortalAuth,async(req,res)=>{
 try{
  const r=await q(`select t.id,t.trip_number,t.status,t.signature_data,t.signature_at,t.delivery_photo,
      t.current_lat,t.current_lng,t.updated_at,c.company,
      coalesce(json_agg(json_build_object('id',s.id,'order',s.stop_order,'address',s.address,
      'planned_time',s.planned_time,'planned_arrival_at',s.planned_arrival_at,
      'actual_arrival_at',s.actual_arrival_at,'arrival_variance_min',s.arrival_variance_min,
      'delivered_at',s.delivered_at,'deviation_note',s.deviation_note,
      'planned_kg',s.planned_kg,'planned_pieces',s.planned_pieces)
      order by s.stop_order) filter(where s.id is not null),'[]') stops
    from trips t join customers c on c.id=t.customer_id
    left join trip_stops s on s.trip_id=t.id
    where t.id=$1 and t.customer_id=$2 group by t.id,c.company`,[req.params.tripId,req.portal.customer_id]);
  if(!r.rows.length)return res.status(404).json({error:"Zustellbeleg nicht gefunden"});
  res.json({trip:r.rows[0]});
 }catch(e){res.status(500).json({error:e.message})}
});
app.get("/api/customer-portal-v130/delivery-proof/:tripId/pdf",v127PortalAuth,async(req,res)=>{
 try{
  const r=await q(`select t.*,c.company customer_company,c.address customer_address,c.city customer_city
    from trips t join customers c on c.id=t.customer_id where t.id=$1 and t.customer_id=$2`,[req.params.tripId,req.portal.customer_id]);
  if(!r.rows.length)return res.status(404).json({error:"Zustellbeleg nicht gefunden"});
  const t=r.rows[0];
  const stops=await q(`select * from trip_stops where trip_id=$1 order by stop_order`,[t.id]);
  res.setHeader("Content-Type","text/html; charset=utf-8");
  res.send(`<!doctype html><html><head><meta charset="utf-8"><title>DDT ${t.trip_number}</title>
  <style>body{font-family:Arial;margin:40px;color:#222}h1{margin-bottom:4px}.box{border:1px solid #bbb;padding:14px;margin:14px 0}table{width:100%;border-collapse:collapse}td,th{border:1px solid #ccc;padding:7px;text-align:left}@media print{button{display:none}}</style></head>
  <body><button onclick="print()">Drucken / PDF speichern</button><h1>Delivery Note / DDT</h1><p><b>Tour:</b> ${t.trip_number}</p>
  <div class="box"><b>Kunde:</b> ${t.customer_company||""}<br>${t.customer_address||""} ${t.customer_city||""}</div>
  <table><tr><th>Stop</th><th>Adresse</th><th>Geplant</th><th>Zugestellt</th><th>Abweichung</th></tr>
  ${stops.rows.map(x=>`<tr><td>${x.stop_order}</td><td>${x.address||""}</td><td>${x.planned_arrival_at||x.planned_time||""}</td><td>${x.delivered_at||""}</td><td>${x.deviation_note||""}</td></tr>`).join("")}</table>
  <div class="box"><b>Digitale Unterschrift:</b><br>${t.signature_data?'<img style="max-width:500px;max-height:180px" src="'+t.signature_data+'">':"Nicht vorhanden"}<br>
  <b>Signiert:</b> ${t.signature_at||"—"}<br><b>GPS:</b> ${t.current_lat||"—"}, ${t.current_lng||"—"}<br>
  <b>Lieferfoto:</b> ${t.delivery_photo?'<br><img style="max-width:500px;max-height:300px" src="'+t.delivery_photo+'">':"Nicht vorhanden"}</div></body></html>`);
 }catch(e){res.status(500).json({error:e.message})}
});


// V131 automatic completion pipeline
async function v131FinalizeDeliveredTrip(tripId){
 const tr=await q(`select t.*,c.company customer_company,c.email customer_email,c.communication_language
   from trips t left join customers c on c.id=t.customer_id where t.id=$1`,[tripId]);
 if(!tr.rows.length) throw new Error("Trip not found");
 const t=tr.rows[0];
 const stops=await q(`select * from trip_stops where trip_id=$1 order by stop_order`,[tripId]);
 if(!stops.rows.length || stops.rows.some(x=>!x.delivered_at)) return {completed:false,reason:"Not all stops delivered"};
 await q(`update trips set status='Delivered',updated_at=now() where id=$1`,[tripId]);

 let inv=await q(`select * from invoices where trip_id=$1 order by issue_date desc limit 1`,[tripId]);
 if(!inv.rows.length && t.customer_id){
   const net=Number(t.price_net||0), vat=Number((net*0.22).toFixed(2)), gross=Number((net+vat).toFixed(2));
   const n=(await q(`select 'INV-'||to_char(current_date,'YYYYMM')||'-'||lpad((count(*)+1)::text,4,'0') n from invoices where issue_date>=date_trunc('month',current_date)`)).rows[0].n;
   inv=await q(`insert into invoices(invoice_number,customer_id,trip_id,due_date,net,vat_rate,vat,gross,status,description)
     values($1,$2,$3,current_date+30,$4,22,$5,$6,'Open',$7) returning *`,
     [n,t.customer_id,tripId,net,vat,gross,"Automatic delivery invoice "+t.trip_number]);
 }
 const invoice=inv.rows[0]||null;
 if(t.customer_email){
   const subject=`Delivery completed · ${t.trip_number}`;
   const body=`Delivery ${t.trip_number} has been completed. Your delivery documents and invoice are available in the customer portal.`;
   const exists=await q(`select id from customer_communication_outbox where trip_id=$1 and subject=$2 limit 1`,[tripId,subject]);
   if(!exists.rows.length) await q(`insert into customer_communication_outbox(customer_id,trip_id,channel,recipient,subject,message,status,attempts)
      values($1,$2,'email',$3,$4,$5,'Queued',0)`,[t.customer_id,tripId,t.customer_email,subject,body]);
 }
 await q(`insert into audit_log(user_id,user_name,role,action,details) values(null,'system','Admin','V131_FINALIZE',$1)`,
   [`Trip ${t.trip_number}: delivery finalized; invoice ${invoice?invoice.invoice_number:'none'}; customer notified queue`]);
 return {completed:true,trip_number:t.trip_number,invoice:invoice?.invoice_number||null};
}
app.post("/api/workflow-v131/finalize/:tripId",auth,roles("Admin","Dispatcher"),async(req,res)=>{
 try{res.json(await v131FinalizeDeliveredTrip(req.params.tripId))}catch(e){res.status(500).json({error:e.message})}
});
app.post("/api/workflow-v131/sweep",auth,roles("Admin","Dispatcher"),async(req,res)=>{
 try{
  const r=await q(`select t.id from trips t where t.status not in('Delivered','Cancelled')
    and exists(select 1 from trip_stops s where s.trip_id=t.id)
    and not exists(select 1 from trip_stops s where s.trip_id=t.id and s.delivered_at is null) limit 100`);
  const results=[];
  for(const x of r.rows) results.push(await v131FinalizeDeliveredTrip(x.id));
  res.json({processed:results.length,results});
 }catch(e){res.status(500).json({error:e.message})}
});


const v131Timer=setInterval(async()=>{try{
 const r=await q(`select t.id from trips t where t.status not in('Delivered','Cancelled')
   and exists(select 1 from trip_stops s where s.trip_id=t.id)
   and not exists(select 1 from trip_stops s where s.trip_id=t.id and s.delivered_at is null) limit 50`);
 for(const x of r.rows) await v131FinalizeDeliveredTrip(x.id);
}catch(e){console.error("V131:",e.message)}},120000);
v131Timer.unref?.();


// V132 invoice/DDT document bundle and automatic customer delivery
let PDFKit;
try{ PDFKit=require("pdfkit"); }catch(e){ PDFKit=null; }

function v132Safe(s){ return String(s??"").replace(/[<>&"]/g,c=>({"<":"&lt;",">":"&gt;","&":"&amp;",'"':"&quot;"}[c])); }
async function v132InvoicePdf(invoice,customer,trip){
 if(!PDFKit) throw new Error("PDFKit not installed");
 return await new Promise((resolve,reject)=>{
  const doc=new PDFKit({size:"A4",margin:50}); const chunks=[];
  doc.on("data",c=>chunks.push(c)); doc.on("end",()=>resolve(Buffer.concat(chunks))); doc.on("error",reject);
  doc.fontSize(20).text("EMERGENCY DELIVERY", {align:"center"});
  doc.moveDown().fontSize(16).text("FATTURA / INVOICE");
  doc.fontSize(10).text(`Numero: ${invoice.invoice_number}`);
  doc.text(`Data: ${invoice.issue_date||""}`);
  doc.text(`Scadenza: ${invoice.due_date||""}`);
  doc.moveDown().fontSize(12).text("Cliente");
  doc.fontSize(10).text(customer.company||"");
  doc.text(customer.address||"");
  doc.text(customer.city||"");
  doc.moveDown().text(`Tour: ${trip?.trip_number||""}`);
  doc.moveDown().fontSize(11).text(`Imponibile: € ${Number(invoice.net||0).toFixed(2)}`);
  doc.text(`IVA ${Number(invoice.vat_rate||0).toFixed(2)}%: € ${Number(invoice.vat||0).toFixed(2)}`);
  doc.fontSize(13).text(`Totale: € ${Number(invoice.gross||0).toFixed(2)}`);
  doc.moveDown().fontSize(9).text("Documento generato automaticamente da Emergency Delivery.");
  doc.end();
 });
}
async function v132DdtPdf(trip,customer,stops){
 if(!PDFKit) throw new Error("PDFKit not installed");
 return await new Promise((resolve,reject)=>{
  const doc=new PDFKit({size:"A4",margin:45}); const chunks=[];
  doc.on("data",c=>chunks.push(c)); doc.on("end",()=>resolve(Buffer.concat(chunks))); doc.on("error",reject);
  doc.fontSize(20).text("EMERGENCY DELIVERY",{align:"center"});
  doc.moveDown().fontSize(16).text("DOCUMENTO DI TRASPORTO / DDT");
  doc.fontSize(10).text(`Tour: ${trip.trip_number||""}`);
  doc.text(`Cliente: ${customer.company||""}`);
  doc.moveDown();
  stops.forEach((x,i)=>{
    doc.fontSize(10).text(`${i+1}. ${x.address||""}`);
    doc.text(`   Consegna: ${x.delivered_at||"—"} | Scostamento: ${x.arrival_variance_min??"—"} min`);
    if(x.deviation_note) doc.text(`   Nota: ${x.deviation_note}`);
    doc.moveDown(0.4);
  });
  doc.moveDown().text(`Firma digitale: ${trip.signature_at||"—"}`);
  doc.text(`GPS: ${trip.current_lat||"—"}, ${trip.current_lng||"—"}`);
  doc.end();
 });
}
async function v132BuildDocuments(tripId){
 const r=await q(`select t.*,c.company customer_company,c.address customer_address,c.city customer_city,c.email customer_email
   from trips t join customers c on c.id=t.customer_id where t.id=$1`,[tripId]);
 if(!r.rows.length) throw new Error("Trip not found");
 const trip=r.rows[0], customer={company:trip.customer_company,address:trip.customer_address,city:trip.customer_city,email:trip.customer_email};
 const ir=await q(`select * from invoices where trip_id=$1 order by issue_date desc limit 1`,[tripId]);
 if(!ir.rows.length) throw new Error("Invoice not found");
 const stops=(await q(`select * from trip_stops where trip_id=$1 order by stop_order`,[tripId])).rows;
 const invoice=ir.rows[0];
 const [invoicePdf,ddtPdf]=await Promise.all([v132InvoicePdf(invoice,customer,trip),v132DdtPdf(trip,customer,stops)]);
 return {trip,customer,invoice,stops,invoicePdf,ddtPdf};
}
app.get("/api/workflow-v132/documents/:tripId",auth,roles("Admin","Dispatcher","Accounting"),async(req,res)=>{
 try{
  const d=await v132BuildDocuments(req.params.tripId);
  res.json({trip_number:d.trip.trip_number,invoice_number:d.invoice.invoice_number,
    invoice_pdf_base64:d.invoicePdf.toString("base64"),ddt_pdf_base64:d.ddtPdf.toString("base64")});
 }catch(e){res.status(500).json({error:e.message})}
});
app.post("/api/workflow-v132/send/:tripId",auth,roles("Admin","Dispatcher","Accounting"),async(req,res)=>{
 try{
  const d=await v132BuildDocuments(req.params.tripId);
  if(!d.customer.email) return res.status(400).json({error:"Customer email missing"});
  const subject=`Delivery documents · ${d.trip.trip_number}`;
  const body=`Attached are the delivery note (DDT) and invoice for ${d.trip.trip_number}.`;
  const exists=await q(`select id from email_outbox where trip_id=$1 and subject=$2 limit 1`,[req.params.tripId,subject]);
  if(exists.rows.length) return res.json({queued:false,reason:"Already queued",outbox_id:exists.rows[0].id});
  // Store the PDFs in a deterministic temporary document folder for the existing SMTP worker.
  const dir=path.join(__dirname,"data","generated-documents");
  fs.mkdirSync(dir,{recursive:true});
  const invPath=path.join(dir,`${d.invoice.invoice_number}.pdf`);
  const ddtPath=path.join(dir,`DDT-${d.trip.trip_number}.pdf`);
  fs.writeFileSync(invPath,d.invoicePdf); fs.writeFileSync(ddtPath,d.ddtPdf);
  const e=await q(`insert into email_outbox(customer_id,trip_id,to_email,subject,body,status,attempts,attachments)
    values($1,$2,$3,$4,$5,'Queued',0,$6) returning id`,
    [d.trip.customer_id,req.params.tripId,d.customer.email,subject,body,JSON.stringify([
      {filename:path.basename(ddtPath),path:ddtPath},{filename:path.basename(invPath),path:invPath}
    ])]);
  await q(`insert into customer_communication_outbox(customer_id,trip_id,channel,recipient,subject,message,status,attempts)
    values($1,$2,'email',$3,$4,$5,'Queued',0)`,
    [d.trip.customer_id,req.params.tripId,d.customer.email,subject,body]);
  res.json({queued:true,outbox_id:e.rows[0].id,attachments:[ddtPath,invPath]});
 }catch(e){res.status(500).json({error:e.message})}
});


// V133 SMTP worker with PDF attachments
function v133AttachmentList(row){
  try{
    const a=typeof row.attachments==="string"?JSON.parse(row.attachments||"[]"):(row.attachments||[]);
    return Array.isArray(a)?a.filter(x=>x&&x.path):[];
  }catch(e){ return []; }
}
async function v133SendEmailRow(row){
  if(!process.env.SMTP_HOST) throw new Error("SMTP not configured");
  const nodemailer=require("nodemailer");
  const transporter=nodemailer.createTransport({
    host:process.env.SMTP_HOST,port:Number(process.env.SMTP_PORT||587),
    secure:String(process.env.SMTP_SECURE||"false")==="true",
    auth:process.env.SMTP_USER?{user:process.env.SMTP_USER,pass:process.env.SMTP_PASS}:undefined
  });
  const attachments=v133AttachmentList(row).map(a=>({
    filename:a.filename||require("path").basename(a.path),
    path:a.path
  })).filter(a=>require("fs").existsSync(a.path));
  return transporter.sendMail({
    from:process.env.SMTP_FROM||process.env.SMTP_USER,
    to:row.to_email,subject:row.subject,text:row.body,attachments
  });
}
async function v133ProcessEmailOutbox(){
  const r=await q(`select * from email_outbox where status in('Queued','Retry') and (next_attempt_at is null or next_attempt_at<=now())
    order by created_at asc limit 25`);
  for(const row of r.rows){
    try{
      const info=await v133SendEmailRow(row);
      await q(`update email_outbox set status='Sent',sent_at=now(),attempts=attempts+1,last_error=null where id=$1`,[row.id]);
      await q(`update customer_communication_outbox set status='Sent',sent_at=now(),last_error=null
        where trip_id=$1 and channel='email' and recipient=$2 and subject=$3`,
        [row.trip_id,row.to_email,row.subject]);
      if(info?.messageId) await q(`update customer_communication_outbox set provider_message_id=$1,provider='smtp' where trip_id=$2 and channel='email' and recipient=$3 and subject=$4`,
        [info.messageId,row.trip_id,row.to_email,row.subject]);
    }catch(e){
      const attempts=Number(row.attempts||0)+1;
      const status=attempts>=5?"Failed":"Retry";
      await q(`update email_outbox set status=$1,attempts=$2,last_error=$3,next_attempt_at=now()+interval '10 minutes' where id=$4`,
        [status,attempts,String(e.message).slice(0,1000),row.id]);
      await q(`update customer_communication_outbox set status=$1,last_error=$2,attempts=$3 where trip_id=$4 and channel='email' and recipient=$5 and subject=$6`,
        [status,String(e.message).slice(0,1000),attempts,row.trip_id,row.to_email,row.subject]);
    }
  }
}


async function v133EnsureEmailColumns(){
 await q(`alter table email_outbox add column if not exists attachments jsonb`);
 await q(`alter table email_outbox add column if not exists sent_at timestamptz`);
 await q(`alter table email_outbox add column if not exists next_attempt_at timestamptz`);
 await q(`alter table email_outbox add column if not exists last_error text`);
 await q(`alter table customer_communication_outbox add column if not exists sent_at timestamptz`);
 await q(`alter table customer_communication_outbox add column if not exists last_error text`);
 await q(`alter table customer_communication_outbox add column if not exists provider text`);
 await q(`alter table customer_communication_outbox add column if not exists provider_message_id text`);
}


const v133Timer=setInterval(()=>v133ProcessEmailOutbox().catch(e=>console.error("V133 SMTP:",e.message)),30000);
v133Timer.unref?.();


app.post("/api/workflow-v133/email-worker",auth,roles("Admin","Dispatcher","Accounting"),async(req,res)=>{
 try{await v133EnsureEmailColumns();await v133ProcessEmailOutbox();res.json({ok:true})}
 catch(e){res.status(500).json({error:e.message})}
});


// V134 document delivery monitor
app.get("/api/workflow-v134/outbox",auth,roles("Admin","Dispatcher","Accounting"),async(req,res)=>{
 try{
  const r=await q(`select e.*,c.company,t.trip_number,
    (select count(*) from customer_communication_outbox o where o.trip_id=e.trip_id and o.channel='email' and o.recipient=e.to_email and o.subject=e.subject) communication_count
    from email_outbox e left join customers c on c.id=e.customer_id left join trips t on t.id=e.trip_id
    order by e.created_at desc limit 250`);
  res.json({items:r.rows});
 }catch(e){res.status(500).json({error:e.message})}
});
app.post("/api/workflow-v134/retry/:id",auth,roles("Admin","Dispatcher","Accounting"),async(req,res)=>{
 try{
  const r=await q(`update email_outbox set status='Queued',next_attempt_at=now(),last_error=null where id=$1 returning id,status`,[req.params.id]);
  if(!r.rows.length)return res.status(404).json({error:"Outbox entry not found"});
  res.json({ok:true,item:r.rows[0]});
 }catch(e){res.status(500).json({error:e.message})}
});
app.post("/api/workflow-v134/resend/:id",auth,roles("Admin","Dispatcher","Accounting"),async(req,res)=>{
 try{
  const r=await q(`select * from email_outbox where id=$1`,[req.params.id]);
  if(!r.rows.length)return res.status(404).json({error:"Outbox entry not found"});
  const x=r.rows[0];
  const e=await q(`insert into email_outbox(customer_id,trip_id,to_email,subject,body,status,attempts,attachments)
    values($1,$2,$3,$4,$5,'Queued',0,$6) returning id`,
    [x.customer_id,x.trip_id,x.to_email,x.subject+" · Resend",x.body,x.attachments||JSON.stringify([])]);
  res.json({ok:true,outbox_id:e.rows[0].id});
 }catch(e){res.status(500).json({error:e.message})}
});


// V135 unified customer communication/document timeline
app.get("/api/communications-v135/timeline/customer/:customerId",auth,roles("Admin","Dispatcher","Accounting"),async(req,res)=>{
 try{
  const cid=req.params.customerId;
  const rows=await q(`select * from (
    select e.created_at,'email' type,e.status status,e.subject title,e.body details,e.to_email recipient,
      e.trip_id,e.id ref_id
    from email_outbox e where e.customer_id=$1
    union all
    select o.created_at,o.channel,o.status,o.subject,o.message,o.recipient,o.trip_id,o.id
    from customer_communication_outbox o where o.customer_id=$1
    union all
    select ce.created_at,'delivery_event',ce.event_status,ce.provider,
      ce.event_payload::text,null,o.trip_id,ce.id
    from communication_delivery_events ce join customer_communication_outbox o on o.id=ce.outbox_id
    where o.customer_id=$1
    union all
    select i.issue_date::timestamptz,'invoice',i.status,i.invoice_number,
      ('Gross: '||i.gross::text),null,i.trip_id,i.id
    from invoices i where i.customer_id=$1
  ) x order by created_at desc limit 500`,[cid]);
  res.json({items:rows.rows});
 }catch(e){res.status(500).json({error:e.message})}
});
app.get("/api/communications-v135/timeline/trip/:tripId",auth,roles("Admin","Dispatcher","Accounting","Driver"),async(req,res)=>{
 try{
  const rows=await q(`select * from (
    select e.created_at,'email' type,e.status status,e.subject title,e.body details,e.to_email recipient,e.id ref_id
      from email_outbox e where e.trip_id=$1
    union all
    select o.created_at,o.channel,o.status,o.subject,o.message,o.recipient,o.id
      from customer_communication_outbox o where o.trip_id=$1
    union all
    select ce.created_at,'delivery_event',ce.event_status,ce.provider,ce.event_payload::text,null,ce.id
      from communication_delivery_events ce join customer_communication_outbox o on o.id=ce.outbox_id where o.trip_id=$1
    union all
    select i.issue_date::timestamptz,'invoice',i.status,i.invoice_number,('Gross: '||i.gross::text),null,i.id
      from invoices i where i.trip_id=$1
  ) x order by created_at desc limit 500`,[req.params.tripId]);
  res.json({items:rows.rows});
 }catch(e){res.status(500).json({error:e.message})}
});


// V136 live communication/document center
app.get("/api/communications-v136/search",auth,roles("Admin","Dispatcher","Accounting"),async(req,res)=>{
 try{
  const term=String(req.query.q||"").trim();
  const status=String(req.query.status||"").trim();
  const type=String(req.query.type||"").trim();
  const limit=Math.min(500,Math.max(1,Number(req.query.limit||100)));
  const rows=await q(`select * from (
    select e.created_at,'email' type,e.status,e.subject title,e.body details,e.to_email recipient,e.trip_id,e.customer_id,e.id ref_id
      from email_outbox e
    union all
    select o.created_at,o.channel,o.status,o.subject,o.message,o.recipient,o.trip_id,o.customer_id,o.id
      from customer_communication_outbox o
    union all
    select i.issue_date::timestamptz,'invoice',i.status,i.invoice_number,('Gross: '||i.gross::text),null,i.trip_id,i.customer_id,i.id
      from invoices i
  ) x
  where ($1='' or coalesce(title,'') ilike '%'||$1||'%' or coalesce(details,'') ilike '%'||$1||'%' or coalesce(recipient,'') ilike '%'||$1||'%')
    and ($2='' or status=$2) and ($3='' or type=$3)
  order by created_at desc limit $4`,[term,status,type,limit]);
  res.json({items:rows.rows});
 }catch(e){res.status(500).json({error:e.message})}
});
app.get("/api/communications-v136/live",auth,roles("Admin","Dispatcher","Accounting"),async(req,res)=>{
 try{
  const r=await q(`select count(*) total,
    count(*) filter(where status='Queued') queued,
    count(*) filter(where status='Retry') retry,
    count(*) filter(where status='Failed') failed,
    count(*) filter(where status='Sent') sent
    from email_outbox where created_at>now()-interval '24 hours'`);
  res.json(r.rows[0]);
 }catch(e){res.status(500).json({error:e.message})}
});

const v136SseClients=new Set();
app.get("/api/communications-v136/stream",auth,roles("Admin","Dispatcher","Accounting"),(req,res)=>{
 res.setHeader("Content-Type","text/event-stream");res.setHeader("Cache-Control","no-cache");res.setHeader("Connection","keep-alive");res.flushHeaders?.();
 v136SseClients.add(res);res.write("event: ready\ndata: {}\n\n");req.on("close",()=>v136SseClients.delete(res));
});
async function v136Broadcast(){
 try{
  const r=await q(`select count(*) total,count(*) filter(where status='Queued') queued,count(*) filter(where status='Retry') retry,count(*) filter(where status='Failed') failed,count(*) filter(where status='Sent') sent from email_outbox where created_at>now()-interval '24 hours'`);
  const msg=`data: ${JSON.stringify(r.rows[0])}\n\n`;for(const c of v136SseClients){try{c.write(msg)}catch(e){v136SseClients.delete(c)}}
 }catch(e){}
}
setInterval(v136Broadcast,5000);

// V136 live communication/document center


async function ensureV48Schema(){
  await pool.query(`
    ALTER TABLE orders ADD COLUMN IF NOT EXISTS planned_trip_id uuid REFERENCES trips(id) ON DELETE SET NULL;
    ALTER TABLE orders ADD COLUMN IF NOT EXISTS planned_at timestamptz;
    ALTER TABLE orders ADD COLUMN IF NOT EXISTS dispatch_note text;
    CREATE INDEX IF NOT EXISTS idx_orders_planned_trip ON orders(planned_trip_id);
  `);
}
ensureV48Schema().catch(err=>console.error("V48 schema init failed:",err));


async function ensureV49Schema(){
  await pool.query(`
    ALTER TABLE trips ADD COLUMN IF NOT EXISTS dispatch_slot integer;
    ALTER TABLE trips ADD COLUMN IF NOT EXISTS dispatch_locked boolean NOT NULL DEFAULT false;
    ALTER TABLE orders ADD COLUMN IF NOT EXISTS dispatch_position integer;
  `);
}
ensureV49Schema().catch(err=>console.error("V49 schema init failed:",err));


async function ensureV50Schema(){
  await pool.query(`
    ALTER TABLE trip_stops ADD COLUMN IF NOT EXISTS dispatch_position integer;
    ALTER TABLE trip_stops ADD COLUMN IF NOT EXISTS planned_revenue_net numeric NOT NULL DEFAULT 0;
  `);
}
ensureV50Schema().catch(err=>console.error("V50 schema init failed:",err));


async function ensureV51Schema(){
  await pool.query(`
    ALTER TABLE trip_stops ADD COLUMN IF NOT EXISTS route_eta_at timestamptz;
    ALTER TABLE trip_stops ADD COLUMN IF NOT EXISTS route_arrival_at timestamptz;
    ALTER TABLE trip_stops ADD COLUMN IF NOT EXISTS route_departure_at timestamptz;
    ALTER TABLE trips ADD COLUMN IF NOT EXISTS route_calculated_at timestamptz;
    ALTER TABLE trips ADD COLUMN IF NOT EXISTS route_total_distance_km numeric;
    ALTER TABLE trips ADD COLUMN IF NOT EXISTS route_total_duration_min integer;
    ALTER TABLE trips ADD COLUMN IF NOT EXISTS route_eta_end_at timestamptz;
  `);
}
ensureV51Schema().catch(err=>console.error("V51 schema init failed:",err));


async function ensureV52Schema(){
  await pool.query(`
    ALTER TABLE customers ADD COLUMN IF NOT EXISTS lat numeric;
    ALTER TABLE customers ADD COLUMN IF NOT EXISTS lng numeric;
    ALTER TABLE customers ADD COLUMN IF NOT EXISTS geocoded_at timestamptz;
    ALTER TABLE trip_stops ADD COLUMN IF NOT EXISTS geocoded_at timestamptz;
    ALTER TABLE trip_stops ADD COLUMN IF NOT EXISTS geocode_source text;
    CREATE INDEX IF NOT EXISTS idx_trip_stops_lat_lng ON trip_stops(lat,lng);
  `);
}
ensureV52Schema().catch(err=>console.error("V52 schema init failed:",err));


async function ensureV55Schema(){
  await pool.query(`
    ALTER TABLE trips ADD COLUMN IF NOT EXISTS gps_status text NOT NULL DEFAULT 'offline';
    ALTER TABLE trips ADD COLUMN IF NOT EXISTS gps_last_accuracy numeric;
    ALTER TABLE trips ADD COLUMN IF NOT EXISTS gps_last_at timestamptz;
  `);
}
ensureV55Schema().catch(err=>console.error("V55 schema init failed:",err));


async function ensureV57Schema(){
  await pool.query(`
    ALTER TABLE trips ADD COLUMN IF NOT EXISTS gps_alert_sent_at timestamptz;
    ALTER TABLE trips ADD COLUMN IF NOT EXISTS live_alert_state text NOT NULL DEFAULT 'normal';
  `);
}
ensureV57Schema().catch(err=>console.error("V57 schema init failed:",err));

// V143 stop drag/drop + automatic route/ETA recalculation

// V143 stop drag/drop + automatic route/ETA recalculation
app.post("/api/dispatch-v143/reorder-stops/:tripId",auth,roles("Admin","Dispatcher"),async(req,res)=>{
  try{
    const tripId=req.params.tripId;
    const stopIds=Array.isArray(req.body?.stop_ids)?req.body.stop_ids:[];
    if(!stopIds.length)return res.status(400).json({error:"stop_ids erforderlich"});
    const trip=(await q(`select id,status,dispatch_locked from trips where id=$1`,[tripId]))[0];
    if(!trip)return res.status(404).json({error:"Tour nicht gefunden"});
    if(trip.dispatch_locked)return res.status(409).json({error:"Tour ist gesperrt"});
    const existing=await q(`select id from trip_stops where trip_id=$1`,[tripId]);
    const allowed=new Set(existing.map(x=>x.id));
    if(stopIds.length!==existing.length || stopIds.some(id=>!allowed.has(id))){
      return res.status(400).json({error:"Stoppliste ist unvollständig oder ungültig"});
    }
    for(let i=0;i<stopIds.length;i++){
      await q(`update trip_stops set stop_order=$1,dispatch_position=$1,planned_sequence=$1 where id=$2 and trip_id=$3`,[i+1,stopIds[i],tripId]);
    }
    let route=null;
    const key=process.env.GOOGLE_ROUTES_API_KEY||"";
    const stops=await q(`select * from trip_stops where trip_id=$1 order by dispatch_position,stop_order,id`,[tripId]);
    const geo=stops.filter(x=>x.lat!=null&&x.lng!=null);
    if(key && geo.length===stops.length && stops.length>=2){
      const origin={location:{latLng:{latitude:Number(stops[0].lat),longitude:Number(stops[0].lng)}}};
      const destination={location:{latLng:{latitude:Number(stops[stops.length-1].lat),longitude:Number(stops[stops.length-1].lng)}}};
      const intermediates=stops.slice(1,-1).map(x=>({location:{latLng:{latitude:Number(x.lat),longitude:Number(x.lng)}}}));
      const rr=await fetch("https://routes.googleapis.com/directions/v2:computeRoutes",{method:"POST",
        headers:{"Content-Type":"application/json","X-Goog-Api-Key":key,"X-Goog-FieldMask":"routes.distanceMeters,routes.duration,routes.staticDuration,routes.polyline.encodedPolyline"},
        body:JSON.stringify({origin,destination,intermediates,travelMode:"DRIVE",routingPreference:"TRAFFIC_AWARE",computeAlternativeRoutes:false})});
      const data=await rr.json();
      if(rr.ok && data.routes?.length){
        const r=data.routes[0];
        const km=Number(r.distanceMeters||0)/1000;
        const min=Math.max(1,Math.round(parseFloat(r.duration||"0s")/60));
        await q(`update trips set route_total_distance_km=$1,route_total_duration_min=$2,route_calculated_at=now(),route_provider='google-routes-v143',route_polyline=$3,route_eta_end_at=now()+($4||' minutes')::interval where id=$5`,
          [km,min,r.polyline?.encodedPolyline||null,min,tripId]);
        route={provider:"google-routes-v143",distance_km:km,duration_min:min};
      }
    }
    if(!route){
      let totalKm=0,totalMin=0;
      const hav=(a,b,c,d)=>{const R=6371,rad=x=>x*Math.PI/180,la=rad(c-a),lo=rad(d-b);const z=Math.sin(la/2)**2+Math.cos(rad(a))*Math.cos(rad(c))*Math.sin(lo/2)**2;return 2*R*Math.asin(Math.sqrt(z))};
      for(let i=0;i<stops.length;i++){
        let km=0,min=0;
        if(i>0&&stops[i-1].lat!=null&&stops[i-1].lng!=null&&stops[i].lat!=null&&stops[i].lng!=null){
          km=hav(Number(stops[i-1].lat),Number(stops[i-1].lng),Number(stops[i].lat),Number(stops[i].lng));
          min=Math.max(1,Math.round(km/45*60));
        }
        totalKm+=km; totalMin+=min;
        await q(`update trip_stops set route_distance_from_prev_km=$1,route_duration_from_prev_min=$2,route_arrival_at=now()+($3||' minutes')::interval where id=$4`,[km,min,totalMin,stops[i].id]);
      }
      await q(`update trips set route_total_distance_km=$1,route_total_duration_min=$2,route_calculated_at=now(),route_provider=$3,route_eta_end_at=now()+($4||' minutes')::interval where id=$5`,
        [totalKm,totalMin,"heuristic-v143",totalMin,tripId]);
      route={provider:"heuristic-v143",distance_km:totalKm,duration_min:totalMin};
    }
    await audit(req,"V143_STOPS_REORDERED",`trip=${tripId};count=${stopIds.length};route=${route.provider}`);
    res.json({ok:true,stop_ids:stopIds,route});
  }catch(e){res.status(400).json({error:e.message})}
});

app.get("/api/dispatch-v143/stops/:tripId",auth,roles("Admin","Dispatcher","Driver"),async(req,res)=>{
  try{
    const trip=(await q(`select id,trip_number,route_total_distance_km,route_total_duration_min,route_eta_end_at,route_provider from trips where id=$1`,[req.params.tripId]))[0];
    if(!trip)return res.status(404).json({error:"Tour nicht gefunden"});
    const stops=await q(`select id,stop_order,dispatch_position,address,customer_name,planned_time,planned_arrival_at,route_arrival_at,delivered_at,planned_kg,planned_pieces,lat,lng from trip_stops where trip_id=$1 order by dispatch_position nulls last,stop_order,id`,[req.params.tripId]);
    res.json({trip,stops});
  }catch(e){res.status(500).json({error:e.message})}
});




// V195 Kalender: Termine und Veranstaltungen
async function ensureCalendarSchema(){
  await q(`CREATE TABLE IF NOT EXISTS calendar_events(
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    title text NOT NULL,
    description text,
    start_date date NOT NULL,
    start_time time,
    end_date date,
    end_time time,
    all_day boolean NOT NULL DEFAULT false,
    location text,
    event_type text NOT NULL DEFAULT 'Termin',
    created_by uuid REFERENCES users(id),
    created_at timestamptz DEFAULT now(),
    updated_at timestamptz DEFAULT now()
  )`);
  await q(`CREATE INDEX IF NOT EXISTS idx_calendar_events_dates ON calendar_events(start_date,end_date)`);
}
const calendarSchemaReady=ensureCalendarSchema().catch(e=>{console.error('Calendar schema init failed:',e);throw e});

app.get('/api/calendar/events',auth,async(req,res)=>{
  try{await calendarSchemaReady;
    const from=req.query.from||'1900-01-01', to=req.query.to||'2999-12-31';
    const rows=await q(`select e.*,u.name as created_by_name from calendar_events e left join users u on u.id=e.created_by where e.start_date <= $2::date and coalesce(e.end_date,e.start_date) >= $1::date order by e.start_date,e.start_time nulls first,e.title`,[from,to]);
    res.json(rows);
  }catch(e){res.status(500).json({error:e.message})}
});
app.post('/api/calendar/events',auth,roles('Admin','Dispatcher','Accounting'),async(req,res)=>{
  try{await calendarSchemaReady;
    const b=req.body||{};
    if(!b.title?.trim()||!b.startDate)return res.status(400).json({error:'Titel und Startdatum erforderlich'});
    const r=await q(`insert into calendar_events(title,description,start_date,start_time,end_date,end_time,all_day,location,event_type,created_by) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) returning *`,[
      b.title.trim(),b.description||'',b.startDate,b.startTime||null,b.endDate||null,b.endTime||null,!!b.allDay,b.location||'',b.eventType||'Termin',req.user.id
    ]);
    await audit(req,'CALENDAR_CREATED',r[0].title); res.status(201).json(r[0]);
  }catch(e){res.status(400).json({error:e.message})}
});
app.patch('/api/calendar/events/:id',auth,roles('Admin','Dispatcher','Accounting'),async(req,res)=>{
  try{await calendarSchemaReady;
    const b=req.body||{}, allowed={title:'title',description:'description',startDate:'start_date',startTime:'start_time',endDate:'end_date',endTime:'end_time',allDay:'all_day',location:'location',eventType:'event_type'};
    const keys=Object.keys(allowed).filter(k=>Object.prototype.hasOwnProperty.call(b,k));
    if(!keys.length)return res.status(400).json({error:'Keine Änderungen'});
    const vals=keys.map(k=>b[k]===undefined||b[k]===''?null:b[k]);
    const set=keys.map((k,i)=>`${allowed[k]}=$${i+1}`).join(',');
    const r=await q(`update calendar_events set ${set},updated_at=now() where id=$${keys.length+1} returning *`,[...vals,req.params.id]);
    if(!r[0])return res.status(404).json({error:'Termin nicht gefunden'});
    await audit(req,'CALENDAR_UPDATED',r[0].title); res.json(r[0]);
  }catch(e){res.status(400).json({error:e.message})}
});
app.delete('/api/calendar/events/:id',auth,roles('Admin','Dispatcher','Accounting'),async(req,res)=>{
  try{await calendarSchemaReady;
    const r=await q(`delete from calendar_events where id=$1 returning *`,[req.params.id]);
    if(!r[0])return res.status(404).json({error:'Termin nicht gefunden'});
    await audit(req,'CALENDAR_DELETED',r[0].title); res.json({ok:true});
  }catch(e){res.status(400).json({error:e.message})}
});

// Single online/server entry point. blitz.cloud supplies PORT (normally 8080).
if (require.main === module) {
  app.listen(Number(PORT), "0.0.0.0", () => {
    console.log(`Emergency Delivery V215 online server listening on ${PORT}`);
  });
}
