const {app,BrowserWindow,dialog}=require("electron");
const path=require("path");
const net=require("net");
let backendLoaded=false;

function findFreePort(start=3000){
  return new Promise((resolve,reject)=>{
    const tryPort=(port)=>{
      const probe=net.createServer();
      probe.once("error",err=>{
        if(err.code==="EADDRINUSE") return tryPort(port+1);
        reject(err);
      });
      probe.once("listening",()=>probe.close(()=>resolve(port)));
      probe.listen(port,"127.0.0.1");
    };
    tryPort(start);
  });
}
async function prepare(){
  process.env.PORT=String(await findFreePort(3000));
  process.env.JWT_SECRET=process.env.JWT_SECRET||"emergency-delivery-local-v164";
  process.env.EMERGENCY_DB_DIR=path.join(app.getPath("userData"),"database");
  process.env.EMERGENCY_CONFIG_DIR=path.join(app.getPath("userData"),"config");
  // V202: preconfigure Gmail address on first launch.
  // Gmail SMTP requires a Google App Password (not the normal Google account password).
  // Existing user settings are preserved and can be changed in E-Mail -> Gmail SMTP.
  const fs=require("fs");
  const smtpDir=process.env.EMERGENCY_CONFIG_DIR;
  const smtpFile=path.join(smtpDir,"smtp.json");
  if(!fs.existsSync(smtpFile)){
    fs.mkdirSync(smtpDir,{recursive:true});
    fs.writeFileSync(smtpFile,JSON.stringify({
      host:"smtp.gmail.com",
      port:587,
      secure:false,
      user:"emergency.delivery@gmail.com",
      pass:"",
      from:"emergency.delivery@gmail.com"
    },null,2),"utf8");
  }
  const bootstrap=require("./bootstrap-db.js");
  try{
    await bootstrap();
  }catch(firstError){
    // PGlite can leave its local WAL/database in an unrecoverable state after
    // an interrupted Windows shutdown. Preserve the old folder and retry once
    // with a fresh local database instead of aborting the whole application.
    const {recoverLocalDb}=require("./local-db.js");
    const recovery=await recoverLocalDb();
    try{ delete require.cache[require.resolve("./bootstrap-db.js")]; }catch(_e){}
    const bootstrapRetry=require("./bootstrap-db.js");
    await bootstrapRetry();
    console.warn("Local database recovered",{firstError:String(firstError),...recovery});
  }
  if(!backendLoaded){require("./server.js");backendLoaded=true}
}
async function createWindow(){
  try{await prepare();}
  catch(e){await dialog.showMessageBox({type:"error",title:"Emergency Delivery – Startfehler",message:e.message,detail:"Die lokale Datenbank konnte nicht initialisiert werden."});app.quit();return}
  const win=new BrowserWindow({width:1440,height:900,minWidth:1100,minHeight:700,autoHideMenuBar:true,backgroundColor:"#ffffff",webPreferences:{contextIsolation:true,nodeIntegration:false}});
  win.webContents.on("did-fail-load",(_e,code,desc,url)=>console.error("Load failed:",code,desc,url));
  await win.loadURL(`http://127.0.0.1:${process.env.PORT}/`);
}
app.whenReady().then(createWindow);
app.on("window-all-closed",()=>{if(process.platform!=="darwin")app.quit()});
