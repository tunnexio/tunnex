import {useState} from 'react';
import {Button, Card, PageHeader, Modal, DataTable, Input} from './ui';
const sites = [
  {name:'Mumbai office', range:'10.20.0.0/24', gateway:'office-gateway', role:'Spoke'},
  {name:'AWS private network', range:'10.30.0.0/24', gateway:'aws-gateway', role:'Public hub'},
];
export function WireGuardDemo({embedded = false, onExit}: {embedded?: boolean; onExit?: () => void}){
  const [tab,setTab]=useState('Connections');
  const [health,setHealth]=useState('Up');
  const [open,setOpen]=useState(false);
  const [selected,setSelected]=useState(true);
  const [first,setFirst]=useState('0');
  const [second,setSecond]=useState('1');
  const [created,setCreated]=useState(true);
  const [search,setSearch]=useState('');
  const [detailTab,setDetailTab]=useState('tunnels');
  return <main className="network-management space-y-5" style={embedded ? undefined : {maxWidth:1200,margin:'0 auto',padding:32}}>
    <div className="flex flex-wrap justify-between gap-3 rounded-lg border border-line p-3 text-sm"><strong>Demo · Dummy data only</strong>{onExit && <Button variant="ghost" size="sm" onClick={onExit}>Exit demo</Button>}<label>Simulated health <select aria-label="Simulated health" className="bg-surface border border-line rounded p-1 ml-2" value={health} onChange={e=>setHealth(e.target.value)}>{['Up','Down','Unknown'].map(x=><option key={x}>{x}</option>)}</select></label></div>
    <PageHeader title={embedded ? "WireGuard demo" : "Site-to-site"} subtitle="Connect your private networks." actions={<Button onClick={()=>setOpen(true)}>Create connection</Button>}/>
    {!embedded && <nav className="workspace-tabs">{['Networks','Connections'].map(x=><button key={x} aria-current={tab===x?'page':undefined} onClick={()=>setTab(x)}>{x}</button>)}</nav>}
    {!embedded && tab==='Networks' ? <Card><h2 className="text-lg font-semibold mb-4">Networks</h2><div className="overflow-auto"><table className="w-full text-sm text-left"><thead><tr>{['Network','Private range','Gateway','Role'].map(x=><th className="p-3" key={x}>{x}</th>)}</tr></thead><tbody>{sites.map(s=><tr className="border-t border-line" key={s.name}><td className="p-3">{s.name}</td><td className="p-3">{s.range}</td><td className="p-3">{s.gateway}</td><td className="p-3">{s.role}</td></tr>)}</tbody></table></div></Card> : <>
      <div className="network-filter-tabs"><strong className="network-filter-active">Tunnex to Tunnex · WireGuard</strong></div>
      <div className="flex items-center justify-between gap-4"><div><h2 className="text-lg font-semibold text-ink-heading">WireGuard VPN connections</h2><p className="text-sm text-ink-secondary">WireGuard · Tunnex gateways</p></div><Button variant="ghost" onClick={()=>setSearch('')}>Reset filter</Button></div>
      <Card className="space-y-4">
        <div className="flex items-center justify-between gap-3"><h3 className="font-semibold text-ink-heading">Connections</h3><span className="text-sm text-ink-secondary">1 loaded</span></div>
        <Input aria-label="Search VPN connections" placeholder="Find a connection" value={search} onChange={e=>setSearch(e.target.value)}/>
        <DataTable failed={false} caption="WireGuard connections" rows={created && `Office to AWS ${sites[Number(first)].name} ${sites[Number(second)].name}`.toLowerCase().includes(search.toLowerCase()) ? [{id:'demo',name:'Office to AWS'}] : []} rowKey={r=>r.id} filterable={false} empty="No matching connections." columns={[
          {key:'name',header:'Connection',cell:r=><button aria-pressed={selected} className={`text-left font-medium hover:underline ${selected?'text-accent':'text-ink-heading'}`} onClick={()=>setSelected(true)}>{r.name}</button>},
          {key:'local',header:'Local network',cell:()=>sites[Number(first)].name},
          {key:'remote',header:'Remote network',cell:()=>sites[Number(second)].name},
          {key:'config',header:'Configuration',cell:()=><span className="rounded border border-line px-2 py-1 text-xs text-ink-secondary">Applied (demo)</span>},
        ]}/>
      </Card>
      {selected && created && <Card>
        <div className="mb-3 flex justify-between"><h3 className="font-semibold text-ink-heading">Office to AWS</h3><Button size="sm" variant="ghost" onClick={()=>setSelected(false)}>Close details</Button></div>
        <p className="mb-3 text-xs text-ink-secondary">WireGuard · Hub and spoke · Demo</p>
        <div role="tablist" aria-label="Connection details" className="mb-5 flex gap-6 border-b border-line">{[['tunnels','Tunnel details'],['details','Details']].map(([id,label])=><button key={id} role="tab" aria-selected={detailTab===id} onClick={()=>setDetailTab(id)} className={`pb-3 text-sm ${detailTab===id?'border-b-2 border-current text-ink-heading':'text-ink-secondary'}`}>{label}</button>)}</div>
        {detailTab==='tunnels' ? <section className="space-y-3">
          <div><h4 className="font-medium text-ink-heading">Tunnel status</h4><p className="text-xs text-ink-secondary">Simulated gateway report</p></div>
          <div className="overflow-x-auto rounded border border-line"><table className="w-full text-left text-sm" aria-label="WireGuard tunnel state"><thead className="border-b border-line bg-surface-inset text-xs text-ink-secondary"><tr>{['Tunnel','Local gateway','Remote gateway','Status','Last handshake','Traffic'].map(label=><th key={label} className="px-4 py-3 font-medium whitespace-nowrap">{label}</th>)}</tr></thead><tbody><tr><th className="px-4 py-4 font-medium whitespace-nowrap">Tunnel 1</th><td className="px-4 py-4 text-xs">{sites[Number(first)].gateway}</td><td className="px-4 py-4 text-xs">{sites[Number(second)].gateway}</td><td className="px-4 py-4"><span className="inline-flex items-center gap-2 font-medium" style={{color:health==='Up'?'#34d399':health==='Down'?'#f87171':'#a1a1aa'}}>● {health}</span></td><td className="px-4 py-4 text-xs whitespace-nowrap">{health==='Up'?'8 seconds ago':health==='Down'?'3 minutes ago':<span aria-label="No data">-</span>}</td><td className="px-4 py-4 text-xs whitespace-nowrap">{health==='Unknown'?<span aria-label="No data">-</span>:'24 MB sent / 18 MB received'}</td></tr></tbody></table></div>
          <details className="rounded border border-line text-sm"><summary className="cursor-pointer px-4 py-3 font-medium text-ink-heading">Tunnel 1 details</summary><dl className="grid sm:grid-cols-2 gap-4 border-t border-line px-4 py-4">{[['Local private range',sites[Number(first)].range],['Remote private range',sites[Number(second)].range],['Local gateway role',sites[Number(first)].role],['Remote gateway role',sites[Number(second)].role]].map(([label,value])=><div key={label}><dt className="text-xs text-ink-secondary">{label}</dt><dd className="mt-1 text-sm">{value}</dd></div>)}</dl></details>
        </section> : <dl className="grid sm:grid-cols-2 gap-5 text-sm">{[['Local network',sites[Number(first)].name],['Remote network',sites[Number(second)].name],['Local ranges',sites[Number(first)].range],['Remote ranges',sites[Number(second)].range],['Protocol','WireGuard'],['Access','Separate access policies apply']].map(([label,value])=><div key={label}><dt className="text-xs text-ink-secondary">{label}</dt><dd className="mt-1">{value}</dd></div>)}</dl>}
      </Card>}

    </>}
    {open && <Modal title="Tunnex to Tunnex · WireGuard" size="wide" onDismiss={()=>setOpen(false)} actions={<><Button variant="ghost" onClick={()=>setOpen(false)}>Cancel</Button><Button disabled={first===second} onClick={()=>{setOpen(false);setCreated(true);setSelected(true);setTab('Connections');}}>Preview connection</Button></>}><div className="grid sm:grid-cols-2 gap-4">{[['Source network',first,setFirst],['Destination network',second,setSecond]].map(([label,value,setter])=><label key={String(label)} className="text-sm">{String(label)}<select className="block w-full border border-line rounded p-3 mt-2 bg-surface" value={String(value)} onChange={e=>(setter as (v:string)=>void)(e.target.value)}>{sites.map((s,i)=><option key={s.name} value={i}>{s.name}</option>)}</select></label>)}</div><p className="text-sm text-ink-secondary mt-4">Existing gateways and ranges are reused. This preview simulates the connection; no configuration is saved.</p>{first===second && <p role="alert" className="text-sm mt-3">Choose two different networks.</p>}</Modal>}
  </main>;
}
