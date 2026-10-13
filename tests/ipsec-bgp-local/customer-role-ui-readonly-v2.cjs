/* SOURCE ONLY by default. Separate headless Chrome profile; no user tab, trace,
   login screenshots, credential logs or fabricated sessions. Authenticated normal form. */
const fs=require('fs'),path=require('path');
const {capturePrivateScreenshot}=require('./customer-role-ui-screenshot.cjs');
const {chromium}=require('/Users/pawangupta/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright');
const args=process.argv.slice(2);if(!args.includes('--execute')){console.log(JSON.stringify({source_only:true,ui:'http://127.0.0.1:25173',roles:['admin','member','ai-view'],views:['desktop','mobile'],mutations:false}));process.exit(0)}
function arg(name){const i=args.indexOf(name);if(i<0||!args[i+1])throw Error('Missing reviewed argument');return args[i+1]}
function privateJSON(file){const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);try{const s=fs.fstatSync(fd);if(!s.isFile()||s.uid!==process.getuid()||(s.mode&0o777)!==0o600||s.size>65536)throw Error('Private input ownership');return JSON.parse(fs.readFileSync(fd,'utf8'))}finally{fs.closeSync(fd)}}
const credentials=privateJSON(arg('--credentials')),pins=privateJSON(arg('--pins')),out=arg('--output'),shots=arg('--screenshots');
const shotStat=fs.lstatSync(shots);if(!shotStat.isDirectory()||shotStat.isSymbolicLink()||shotStat.uid!==process.getuid()||(shotStat.mode&0o777)!==0o700||fs.readdirSync(shots).length)throw Error('Fresh private screenshots directory required');
if(pins.root_reviewed!==true||pins.org_id!=='01a1161a-906c-7074-9e80-dd318fc2c1eb'||pins.ui!=='http://127.0.0.1:25173'||credentials.length!==3||new Set(credentials.map(x=>x.role)).size!==3||!['admin','member','ai-view'].every(r=>credentials.some(x=>x.role===r)))throw Error('Reviewed principals required');
for(const c of credentials)if(c.user_id!==pins.principals[c.role]||!c.email||!c.password)throw Error('Principal mismatch');
const fd=fs.openSync(out,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
const receipt={source_only:false,base:pins.ui,views:[],application_mutations_performed:false,auth_mode:'normal login form',started_at:new Date().toISOString()};
let browser;const deadline=setTimeout(()=>{receipt.hard_deadline_expired=true;browser?.close().catch(()=>{});},180000);
(async()=>{
 browser=await chromium.launch({channel:'chrome',headless:true});
 for(const c of credentials)for(const viewport of [{name:'desktop',width:1440,height:1000},{name:'mobile',width:390,height:844}]){
  const context=await browser.newContext({viewport:{width:viewport.width,height:viewport.height}});const page=await context.newPage();page.setDefaultTimeout(15000);
  const result={phase:'context-ready',role:c.role,user_id:c.user_id,viewport:viewport.name,requests:[]};receipt.views.push(result);
  // Block all application writes even if accidental UI behavior submits one.
  await context.route('**/api/**',async route=>{const req=route.request();const url=new URL(req.url());if(url.origin!==pins.ui)throw Error('Unexpected API origin');const login=req.method()==='POST'&&url.pathname==='/api/v1/auth/login';if(!['GET','HEAD'].includes(req.method())&&!login){result.blocked_application_write=true;await route.abort();return}await route.continue()});
  page.on('response',r=>{const u=new URL(r.url());if(u.pathname.startsWith('/api/'))result.requests.push({method:r.request().method(),path:u.pathname,status:r.status()})});
  try{
   result.phase='login';await page.goto(pins.ui+'/login');await page.getByLabel('Email',{exact:true}).fill(c.email);await page.getByLabel('Password',{exact:true}).fill(c.password);await page.getByRole('button',{name:'Sign in',exact:true}).click();await page.waitForURL(u=>u.pathname!=='/login');
   result.phase='authenticated-identity';
   const meResponse=await page.request.get(pins.ui+'/api/v1/auth/me');if(meResponse.status()!==200)throw Error('Identity read refused');const me=await meResponse.json();if(me.id!==c.user_id||me.cp_admin===true||me.email_verified!==true)throw Error('Authenticated principal mismatch');
   const membersResponse=await page.request.get(pins.ui+'/api/v1/organizations/'+pins.org_id+'/members');if(membersResponse.status()!==200)throw Error('Membership read refused');const members=await membersResponse.json();if(!Array.isArray(members)||members.filter(m=>m.user_id===c.user_id).length!==1||members.find(m=>m.user_id===c.user_id).role!==c.role)throw Error('Authenticated role mismatch');result.authenticated_user_verified=true;result.actual_role=c.role;result.cp_admin=false;
   result.phase='site-navigation';await page.goto(pins.ui+'/site-to-site');await page.getByRole('heading',{name:'Site-to-site',exact:true}).waitFor();
   // Select actual rendered radio by its observed value, never coordinate click.
   result.phase='ipsec-radio';await page.locator('input[type=radio][name=connection-purpose][value=ipsec]').check();
   const table=page.getByRole('table',{name:'IPsec connections',exact:true});await table.waitFor();
   result.phase='provider-details';for(const provider of pins.providers){const button=table.getByRole('button',{name:provider.name,exact:true});await button.click();await page.getByRole('region',{name:'Tunnel status',exact:true}).waitFor();result.provider_ids??=[];result.provider_ids.push(provider.id);result.tunnel_columns=await page.getByRole('table',{name:'IPsec tunnel state',exact:true}).getByRole('columnheader').allTextContents()}
   const screenshot=path.join(shots,c.role+'-'+viewport.name+'-authenticated-site.png');await capturePrivateScreenshot(page,screenshot);result.screenshot=screenshot;
   result.phase='role-assertion';const create=page.getByRole('button',{name:'Create connection',exact:true});result.manage_visible=await create.count()>0;
   if(c.role==='admin'){
    result.phase='create-chooser';if(!result.manage_visible)throw Error('Admin management missing');await create.click();await page.getByRole('button',{name:/Cloud \/ Firewall/}).click();await page.getByRole('button',{name:/^AWS/}).click();
    const dialog=page.getByRole('dialog',{name:'New IPsec connection',exact:true});await dialog.waitFor();const routing=dialog.getByLabel('Routing',{exact:true});if(await routing.inputValue()!=='ipv4-static')throw Error('Static default changed');result.static_default=true;
    result.phase='bgp-form-read';await routing.selectOption('ipv4-bgp');await dialog.getByText('BGP settings',{exact:true}).waitFor();await dialog.getByLabel('Maximum prefixes per peer',{exact:true}).waitFor();await dialog.getByText('Approved local ranges are advertised. Only the exact remote ranges above are accepted. Learning routes does not grant application access.',{exact:true}).waitFor();result.bgp_form_warning=true;
    await routing.selectOption('ipv4-static');if(await dialog.getByText('BGP settings',{exact:true}).count())throw Error('BGP fields remained static');await page.keyboard.press('Escape');
   }else if(result.manage_visible||await page.getByRole('button',{name:/^(Disable|Enable|Delete|Rotate keys for) /}).count())throw Error('Unprivileged management visible');
   if(result.blocked_application_write)throw Error('Unexpected application write attempted');result.phase='complete';result.passed=true;
  }catch(error){result.passed=false;result.error_type=error.name;throw Error('Role UI assertion failed')}
  finally{await context.close()}
 }
 receipt.completed=true;
})().catch(error=>{receipt.completed=false;receipt.error_type=error.name;process.exitCode=1}).finally(async()=>{clearTimeout(deadline);if(browser)await browser.close();fs.writeFileSync(fd,JSON.stringify(receipt,null,2));fs.fsyncSync(fd);fs.closeSync(fd);const dir=fs.openSync(path.dirname(out),fs.constants.O_RDONLY);fs.fsyncSync(dir);fs.closeSync(dir);console.log(JSON.stringify({completed:receipt.completed,output:out,secrets_logged:false}))});
