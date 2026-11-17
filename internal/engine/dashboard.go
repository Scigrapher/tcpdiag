package engine

// dashboard is a dependency-free live view. It polls /stats so one operator can
// watch both directions from whichever machine they happen to be sitting at.
const dashboard = `<!doctype html>
<html><head><meta charset="utf-8"><title>tcpdiag</title>
<meta http-equiv="refresh" content="2">
<style>
 body{font:13px/1.5 ui-monospace,Menlo,Consolas,monospace;background:#0f1115;color:#d7dae0;margin:18px}
 h1{font-size:16px;margin:0 0 4px} h2{font-size:13px;color:#8b949e;margin:18px 0 6px;text-transform:uppercase;letter-spacing:.08em}
 table{border-collapse:collapse;margin:6px 0} td,th{padding:2px 12px 2px 0;text-align:right} th{color:#8b949e;font-weight:normal;text-align:right}
 td:first-child,th:first-child{text-align:left;color:#8b949e}
 .good{color:#3fb950}.bad{color:#f85149}.warn{color:#d29922}.dim{color:#8b949e}
 .card{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:10px 14px;margin:10px 0}
 .kpi{display:inline-block;margin-right:26px}
 .kpi b{display:block;font-size:20px}
</style></head><body>
<h1>tcpdiag</h1><div class="dim">auto-refresh 2s &middot; <a style="color:#58a6ff" href="/report">markdown report</a> &middot; <a style="color:#58a6ff" href="/stats">raw stats</a> &middot; <a style="color:#58a6ff" href="/peers">peers</a></div>
<div id="app">loading&hellip;</div>
<script>
function cls(v, warn, bad){ return v>=bad?'bad':(v>=warn?'warn':'good') }
function kpi(l,v,c){ return '<div class="kpi"><span class="dim">'+l+'</span><b class="'+(c||'')+'">'+v+'</b></div>' }
function card(t,s){
  if(!s) return '';
  var h='<div class="card"><h2>'+t+'</h2>';
  h+=kpi('Mb/s out', s.mbps_sent?s.mbps_sent.toFixed(1):'0');
  h+=kpi('Mb/s in', s.mbps_recv?s.mbps_recv.toFixed(1):'0');
  h+=kpi('retrans', s.retrans_sent, s.retrans_sent>0?'warn':'good');
  h+=kpi('fast rtx', s.fast_retrans, s.fast_retrans>0?'warn':'good');
  h+=kpi('rto rtx', s.rto_retrans, s.rto_retrans>0?'bad':'good');
  h+=kpi('spurious', s.spurious_retrans, s.spurious_retrans>0?'bad':'good');
  h+=kpi('dup ack', s.dup_acks_recv, s.dup_acks_recv>50?'warn':'good');
  h+=kpi('missing', s.blocks_missing, s.blocks_missing>0?'bad':'good');
  h+=kpi('out-of-order', s.out_of_order_segs, s.out_of_order_segs>0?'warn':'good');
  h+=kpi('late', s.blocks_late, s.blocks_late>0?'warn':'good');
  h+=kpi('chain bad', s.chain_mismatch, s.chain_mismatch>0?'bad':'good');
  h+=kpi('zero win', s.zero_window_adv+s.zero_window_recv, (s.zero_window_adv+s.zero_window_recv)>0?'bad':'good');
  h+=kpi('rtt ms', s.rtt_ewms?s.rtt_ewms.toFixed(2):'0');
  h+=kpi('rto ms', s.rto_ms?s.rto_ms.toFixed(0):'0');
  h+=kpi('cwnd', s.cwnd);
  h+='</div>';
  return h
}
fetch('/stats').then(r=>r.json()).then(d=>{
  var h='';
  h+='<div class="dim">self '+ (d.self&&d.self.name||'?') +' &middot; '+d.elapsed+'</div>';
  for (var id in d.sessions){
    var s=d.sessions[id];
    h+='<h2>'+ (s.peer_name||id) +' &middot; '+(s.peer_ip||'')+'</h2>';
    h+=card('kernel stack (local view)', s.kernel_local);
    h+=card('kernel stack (reported by peer)', s.kernel_peer);
    h+=card('raw stack (local view)', s.raw_local);
    h+=card('raw stack (reported by peer)', s.raw_peer);
    h+=card('wire observation', s.observed);
  }
  document.getElementById('app').innerHTML = h || '<div class="dim">no sessions yet</div>';
});
</script></body></html>
`
