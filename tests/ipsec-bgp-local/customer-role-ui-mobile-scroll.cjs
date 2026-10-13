/* Source-only default. Normal synthetic admin login; separate headless browser. */
const fs=require('fs'),path=require('path');
const {chromium}=require('/Users/pawangupta/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright');
const args=process.argv.slice(2);if(!args.includes('--execute')){console.log(JSON.stringify({source_only:true,scope:'admin mobile horizontal table scrolling',application_writes:false}));process.exit(0)}
function arg(k){const n=args.indexOf(k);if(n<0||!args[n+1])throw Error('Reviewed arguments required');return args[n+1]}
function privateJSON(p){const fd=fs.openSync(p,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);try{const st=fs.fstatSync(fd);if(!st.isFile()||st.uid!==process.getuid()||(st.mode&0o777)!==0o600||st.size>65536)throw Error('Private input rejected');return JSON.parse(fs.readFileSync(fd,'utf8'))}finally{fs.closeSync(fd)}}
const credentials=privateJSON(arg('--credentials')),pins=privateJSON(arg('--pins')),out=arg('--output'),shots=arg('--screenshots');
const c=credentials.find(v=>v.role==='admin');if(!c||c.user_id!==pins.principals.admin||pins.root_reviewed!==true||pins.ui!=='http://127.0.0.1:25173'||pins.org_id!=='01a1161a-906c-7074-9e80-dd318fc2c1eb')throw Error('Admin binding rejected');
const st=fs.lstatSync(shots);if(!st.isDirectory()||st.isSymbolicLink()||st.uid!==process.getuid()||(st.mode&0o777)!==0o700||fs.readdirSync(shots).length)throw Error('Fresh private screenshots required');
const fd=fs.openSync(out,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
const receipt={scope:'admin mobile390 read-only table scrolling',user_id:c.user_id,phase:'start',application_writes:false,started_at:new Date().toISOString()};let browser;
const deadline=setTimeout(()=>{receipt.deadline_expired=true;browser?.close().catch(()=>{})},90000);
async function screenshot(page,name){if(await page.getByLabel('Password',{exact:true}).count())throw Error('Unsafe authenticated screenshot');const p=path.join(shots,name+'.png');if(fs.existsSync(p))throw Error('Screenshot exists');await page.screenshot({path:p,fullPage:true});fs.chmodSync(p,0o600);return p}
async function pageBounds(page){return page.evaluate(()=>({client:document.documentElement.clientWidth,scroll:document.documentElement.scrollWidth,bodyScroll:document.body.scrollWidth}))}
(async()=>{
 browser=await chromium.launch({channel:'chrome',headless:true});const context=await browser.newContext({viewport:{width:390,height:844}}),page=await context.newPage();page.setDefaultTimeout(15000);
 await context.route('**/api/**',async route=>{const r=route.request(),u=new URL(r.url());if(u.origin!==pins.ui||(!['GET','HEAD'].includes(r.method())&&!(r.method()==='POST'&&u.pathname==='/api/v1/auth/login'))){receipt.blocked_write=true;await route.abort();return}await route.continue()});
 receipt.phase='login';await page.goto(pins.ui+'/login');await page.getByLabel('Email',{exact:true}).fill(c.email);await page.getByLabel('Password',{exact:true}).fill(c.password);await page.getByRole('button',{name:'Sign in',exact:true}).click();await page.waitForURL(u=>u.pathname!=='/login');
 receipt.phase='identity';const meResponse=await page.request.get(pins.ui+'/api/v1/auth/me');if(meResponse.status()!==200)throw Error('Identity refused');const me=await meResponse.json();if(me.id!==c.user_id||me.cp_admin===true||!me.email_verified)throw Error('Wrong admin');const response=await page.request.get(pins.ui+'/api/v1/organizations/'+pins.org_id+'/members');if(response.status()!==200)throw Error('Role refused');const members=await response.json();if(!Array.isArray(members)||members.filter(m=>m.user_id===c.user_id).length!==1||members.find(m=>m.user_id===c.user_id).role!=='admin')throw Error('Wrong role');receipt.authenticated_admin_verified=true;
 receipt.phase='site';await page.goto(pins.ui+'/site-to-site');await page.getByRole('radio',{name:/To a cloud VPN/}).click();await page.waitForURL(u=>u.searchParams.get('method')==='ipsec');const table=page.getByRole('table',{name:'IPsec connections',exact:true});await table.waitFor();
 receipt.before_bounds=await pageBounds(page);if(receipt.before_bounds.scroll>receipt.before_bounds.client+1||receipt.before_bounds.bodyScroll>receipt.before_bounds.client+1)throw Error('Page horizontal overflow');
 const create=page.getByRole('button',{name:'Create connection',exact:true});if(await create.count()!==1)throw Error('Admin management missing');
 receipt.providers=[];
 for(const provider of pins.providers){
  receipt.phase='details';await table.getByRole('button',{name:provider.name,exact:true}).click();const details=page.getByRole('table',{name:'IPsec tunnel state',exact:true});await details.waitFor();await details.scrollIntoViewIfNeeded();
  const before=await details.evaluate(t=>{let e=t.parentElement;while(e&&!(e.scrollWidth>e.clientWidth+1&&['auto','scroll'].includes(getComputedStyle(e).overflowX)))e=e.parentElement;if(!e)throw Error('No confined horizontal scroller');const r=e.getBoundingClientRect();return {left:e.scrollLeft,client:e.clientWidth,scroll:e.scrollWidth,x:r.x,right:r.right}});
  if(before.x< -1||before.right>391||before.scroll<=before.client)throw Error('Invalid confined table');
  const scrolled=await details.evaluate(t=>{let e=t.parentElement;while(e&&!(e.scrollWidth>e.clientWidth+1&&['auto','scroll'].includes(getComputedStyle(e).overflowX)))e=e.parentElement;e.scrollLeft=e.scrollWidth;return e.scrollLeft});if(scrolled<=before.left)throw Error('Table did not scroll');
  const observed=[];for(const name of ['IPsec status','BGP peer','Accepted prefixes','Installed prefixes','Last observed']){
   const h=details.getByRole('columnheader',{name,exact:true});await h.scrollIntoViewIfNeeded();const b=await h.boundingBox();if(!b||b.x< -1||b.x+b.width>391)throw Error('Column not brought into mobile viewport');observed.push(name);
  }
  if(await create.count()!==1)throw Error('Admin management disappeared');const bounds=await pageBounds(page);if(bounds.scroll>bounds.client+1||bounds.bodyScroll>bounds.client+1)throw Error('Page overflow after scroll');
  receipt.providers.push({id:provider.id,scroller_before:before,scroll_left_after:scrolled,columns_visible_by_scrolling:observed,bounds,screenshot:await screenshot(page,provider.id+'-mobile-scrolled')});
 }
 if(receipt.blocked_write)throw Error('Application write attempted');receipt.phase='complete';receipt.completed=true;await context.close();
})().catch(e=>{receipt.completed=false;receipt.error_type=e.name;process.exitCode=1}).finally(async()=>{clearTimeout(deadline);if(browser)await browser.close();fs.writeFileSync(fd,JSON.stringify(receipt,null,2));fs.fsyncSync(fd);fs.closeSync(fd);const d=fs.openSync(path.dirname(out),fs.constants.O_RDONLY);fs.fsyncSync(d);fs.closeSync(d);console.log(JSON.stringify({completed:receipt.completed,phase:receipt.phase,output:out,secrets_logged:false}))});
