/* ══════════════════════════════════════════════
   charts.js v2.0 — SOC Premium Charts
══════════════════════════════════════════════ */
'use strict';

const Charts = (() => {
  const reg = {};

  function destroy(id) {
    if (reg[id]) { try { reg[id].destroy(); } catch(e){} delete reg[id]; }
  }
  function save(id, inst) { reg[id] = inst; }

  function tc() {
    const dark = (localStorage.getItem('netsec-theme')||'dark')==='dark';
    return {
      grid:    dark?'rgba(255,255,255,0.04)':'rgba(0,0,0,0.05)',
      tick:    dark?'#4a5568':'#94a3b8',
      tooltip: dark?'#111827':'#ffffff',
      ttText:  dark?'#e2e8f0':'#0f172a',
      border:  dark?'#1e2d45':'#e2e8f0',
    };
  }

  function tooltipBase() {
    const c = tc();
    return {
      backgroundColor: c.tooltip,
      titleColor:      c.ttText,
      bodyColor:       tc().tick,
      borderColor:     c.border,
      borderWidth:     1,
      padding:         10,
      cornerRadius:    8,
    };
  }

  function axisBase() {
    const c = tc();
    return {
      x: {
        grid:{ color:c.grid, drawTicks:false },
        ticks:{ color:c.tick, font:{size:10}, maxRotation:0 },
        border:{ display:false },
      },
      y: {
        grid:{ color:c.grid, drawTicks:false },
        ticks:{ color:c.tick, font:{size:10} },
        border:{ display:false },
      }
    };
  }

  /* ── Sparkline ── */
  function sparkline(id, data, color) {
    const el = document.getElementById(id);
    if (!el) return;
    destroy(id);
    save(id, new Chart(el, {
      type:'line',
      data:{
        labels: data.map((_,i)=>i),
        datasets:[{ data, borderColor:color, borderWidth:1.5,
          fill:true, backgroundColor:color+'15',
          tension:0.45, pointRadius:0 }]
      },
      options:{
        responsive:true, maintainAspectRatio:false,
        animation:{duration:400},
        plugins:{legend:{display:false},tooltip:{enabled:false}},
        scales:{x:{display:false},y:{display:false}},
      }
    }));
  }

  /* ── Network Activity ── */
  function buildNetwork(days) {
    const el = document.getElementById('networkChart');
    if (!el) return;
    destroy('networkChart');

    const now=new Date(), d=parseInt(days)||7;
    const labels=[],normal=[],threats=[],inbound=[],outbound=[];
    const seed = window._netSecSeed||42;

    for(let i=d-1;i>=0;i--) {
      const dt=new Date(now-i*86400000);
      const isWE=dt.getDay()===0||dt.getDay()===6;
      labels.push(dt.toLocaleDateString('fr-FR',{day:'2-digit',month:'short'}));
      const base=450+Math.sin((i+seed)*0.7)*110+(isWE?-130:0);
      normal.push(Math.max(120,Math.round(base+Math.cos(i*1.3)*70)));
      threats.push(Math.max(10,Math.round(80+Math.sin((i+seed)*1.4)*45+(i===1||i===d-2?90:0))));
      inbound.push(Math.max(80,Math.round(base*0.6+Math.sin(i*0.9)*60)));
      outbound.push(Math.max(50,Math.round(base*0.35+Math.cos(i*1.1)*40)));
    }

    const c=tc();
    save('networkChart', new Chart(el,{
      type:'line',
      data:{
        labels,
        datasets:[
          {label:'Trafic normal',data:normal,borderColor:'#3b82f6',backgroundColor:'rgba(59,130,246,0.06)',borderWidth:2.5,fill:true,tension:0.42,pointRadius:3,pointHoverRadius:6,pointBackgroundColor:'#3b82f6',pointBorderColor:'#080c14',pointBorderWidth:2},
          {label:'Menaces',data:threats,borderColor:'#ef4444',backgroundColor:'rgba(239,68,68,0.05)',borderWidth:2,fill:true,tension:0.42,pointRadius:3,pointHoverRadius:6,pointBackgroundColor:'#ef4444',pointBorderColor:'#080c14',pointBorderWidth:2},
          {label:'Entrant',data:inbound,borderColor:'#10b981',backgroundColor:'rgba(16,185,129,0.04)',borderWidth:1.5,fill:false,tension:0.42,pointRadius:2,borderDash:[4,4]},
          {label:'Sortant',data:outbound,borderColor:'#8b5cf6',backgroundColor:'rgba(139,92,246,0.04)',borderWidth:1.5,fill:false,tension:0.42,pointRadius:2,borderDash:[4,4]},
        ]
      },
      options:{
        responsive:true,maintainAspectRatio:false,
        interaction:{mode:'index',intersect:false},
        animation:{duration:700,easing:'easeInOutQuart'},
        plugins:{
          legend:{
            display:true,
            position:'top',
            align:'end',
            labels:{color:c.tick,font:{size:10},boxWidth:10,usePointStyle:true,pointStyle:'circle'}
          },
          tooltip:Object.assign(tooltipBase(),{
            callbacks:{label:ctx=>` ${ctx.dataset.label}: ${ctx.raw} req/s`}
          })
        },
        scales:Object.assign(axisBase(),{
          y:{...axisBase().y,beginAtZero:true,ticks:{...axisBase().y.ticks,callback:v=>v+'/s'}}
        })
      }
    }));
  }

  /* ── Threat Donut ── */
  function buildThreat(critical,high,medium,low) {
    const el=document.getElementById('threatChart');
    if (!el) return;
    destroy('threatChart');
    const total=critical+high+medium+low;
    const data=total>0?[critical,high,medium,low]:[35,28,22,15];
    save('threatChart', new Chart(el,{
      type:'doughnut',
      data:{
        labels:['Critique','Élevée','Moyenne','Faible'],
        datasets:[{data,
          backgroundColor:['rgba(239,68,68,0.85)','rgba(245,158,11,0.85)','rgba(202,138,4,0.8)','rgba(59,130,246,0.8)'],
          borderColor:['#ef4444','#f59e0b','#ca8a04','#3b82f6'],
          borderWidth:1,hoverOffset:8,borderRadius:4,
        }]
      },
      options:{
        responsive:true,maintainAspectRatio:false,
        cutout:'70%',
        animation:{duration:900,easing:'easeInOutQuart'},
        plugins:{
          legend:{display:false},
          tooltip:Object.assign(tooltipBase(),{
            callbacks:{
              label:ctx=>{
                const t=ctx.dataset.data.reduce((a,b)=>a+b,0);
                return ` ${ctx.label}: ${ctx.raw} (${t>0?Math.round(ctx.raw/t*100):0}%)`;
              }
            }
          })
        }
      }
    }));
  }

  /* ── Severity Trend ── */
  function buildSeverityTrend() {
    const el=document.getElementById('severityChart');
    if (!el) return;
    destroy('severityChart');
    const labels=['Lun','Mar','Mer','Jeu','Ven','Sam','Dim'];
    const seed=window._netSecSeed||42;
    const gen=(base,amp)=>labels.map((_,i)=>Math.max(0,Math.round(base+Math.sin((i+seed)*0.8)*amp)));
    const c=tc();
    save('severityChart', new Chart(el,{
      type:'bar',
      data:{
        labels,
        datasets:[
          {label:'Critical',data:gen(8,6),backgroundColor:'rgba(239,68,68,0.7)',borderRadius:3,stack:'s'},
          {label:'High',data:gen(15,10),backgroundColor:'rgba(245,158,11,0.7)',borderRadius:3,stack:'s'},
          {label:'Medium',data:gen(20,12),backgroundColor:'rgba(202,138,4,0.6)',borderRadius:3,stack:'s'},
          {label:'Low',data:gen(12,8),backgroundColor:'rgba(59,130,246,0.5)',borderRadius:3,stack:'s'},
        ]
      },
      options:{
        responsive:true,maintainAspectRatio:false,
        animation:{duration:700},
        interaction:{mode:'index',intersect:false},
        plugins:{
          legend:{display:true,position:'top',align:'end',labels:{color:c.tick,font:{size:10},boxWidth:10}},
          tooltip:tooltipBase()
        },
        scales:Object.assign(axisBase(),{y:{...axisBase().y,stacked:true,beginAtZero:true,ticks:{...axisBase().y.ticks,callback:v=>v+''}},x:{...axisBase().x,stacked:true}})
      }
    }));
  }

  /* ── Top Protocols ── */
  function buildTopProtocols() {
    const el=document.getElementById('protocolsChart');
    if (!el) return;
    destroy('protocolsChart');
    const c=tc();
    save('protocolsChart', new Chart(el,{
      type:'bar',
      data:{
        labels:['TCP','UDP','HTTP','HTTPS','DNS','SSH','ICMP','SMB'],
        datasets:[{
          label:'Événements',
          data:[450,280,380,520,210,95,140,65],
          backgroundColor:[
            'rgba(59,130,246,0.7)','rgba(16,185,129,0.7)','rgba(245,158,11,0.7)',
            'rgba(139,92,246,0.7)','rgba(6,182,212,0.7)','rgba(239,68,68,0.7)',
            'rgba(234,179,8,0.7)','rgba(236,72,153,0.7)'
          ],
          borderRadius:4, borderSkipped:false,
        }]
      },
      options:{
        responsive:true,maintainAspectRatio:false,
        animation:{duration:600},
        indexAxis:'y',
        plugins:{legend:{display:false},tooltip:tooltipBase()},
        scales:Object.assign(axisBase(),{x:{...axisBase().x,beginAtZero:true,ticks:{...axisBase().x.ticks,callback:v=>v}},y:{...axisBase().y,grid:{display:false}}})
      }
    }));
  }

  /* ── Top Ports ── */
    function buildTopPorts() {
    const el = document.getElementById('portsChart');
    if (!el) return;
    destroy('portsChart');
    save('portsChart', new Chart(el,{
      type:'doughnut',
      data:{
        labels:['443 HTTPS','80 HTTP','22 SSH','445 SMB','3389 RDP','53 DNS','21 FTP','4444 MSF','8080 HTTP-alt','23 Telnet'],
        datasets:[{
          data:[35,22,15,10,8,5,3,2,2,1],
          backgroundColor:[
            'rgba(59,130,246,0.8)','rgba(16,185,129,0.8)','rgba(245,158,11,0.8)',
            'rgba(239,68,68,0.8)','rgba(139,92,246,0.8)','rgba(6,182,212,0.8)',
            'rgba(234,179,8,0.8)','rgba(236,72,153,0.8)','rgba(20,184,166,0.8)',
            'rgba(249,115,22,0.8)'
          ],
          borderColor:'transparent',hoverOffset:6,borderRadius:3,
        }]
      },
      options:{
        responsive:true,maintainAspectRatio:false,
        cutout:'60%',animation:{duration:700},
        plugins:{
          legend:{
            display:true,position:'right',
            labels:{color:tc().tick,font:{size:10},boxWidth:10,padding:8}
          },
          tooltip:tooltipBase()
        }
      }
    }));
  }

  /* ── Monitor Chart ── */
  const monHistory={cpu:[],ram:[]};

  function buildMonitor(cpuArr,ramArr) {
    const el=document.getElementById('monitorChart');
    if (!el) return;
    destroy('monitorChart');
    const len=Math.max(cpuArr.length,ramArr.length);
    const labels=Array.from({length:len},(_,i)=>i===len-1?'Now':'-'+(len-1-i)+'m');
    const c=tc();
    save('monitorChart', new Chart(el,{
      type:'line',
      data:{
        labels,
        datasets:[
          {label:'CPU %',data:cpuArr,borderColor:'#3b82f6',backgroundColor:'rgba(59,130,246,0.07)',borderWidth:2,fill:true,tension:0.4,pointRadius:2,pointHoverRadius:5,pointBackgroundColor:'#3b82f6'},
          {label:'RAM %',data:ramArr,borderColor:'#8b5cf6',backgroundColor:'rgba(139,92,246,0.06)',borderWidth:2,fill:true,tension:0.4,pointRadius:2,pointHoverRadius:5,pointBackgroundColor:'#8b5cf6'}
        ]
      },
      options:{
        responsive:true,maintainAspectRatio:false,
        animation:{duration:350},
        interaction:{mode:'index',intersect:false},
        plugins:{
          legend:{display:true,labels:{color:c.tick,font:{size:10},boxWidth:10,usePointStyle:true}},
          tooltip:Object.assign(tooltipBase(),{callbacks:{label:ctx=>` ${ctx.dataset.label}: ${ctx.raw}%`}})
        },
        scales:Object.assign(axisBase(),{y:{...axisBase().y,min:0,max:100,ticks:{...axisBase().y.ticks,callback:v=>v+'%'}}})
      }
    }));
  }

  /* ── Security Score Ring ── */
  function buildScoreRing(score) {
    const svg=document.getElementById('score-ring-svg');
    if (!svg) return;
    const r=54,circ=2*Math.PI*r;
    const pct=Math.min(100,Math.max(0,score));
    const offset=circ-(pct/100)*circ;
    const col=pct>=80?'#10b981':pct>=60?'#f59e0b':'#ef4444';
    svg.innerHTML=`
      <circle cx="60" cy="60" r="${r}" fill="none" stroke="var(--border)" stroke-width="7"/>
      <circle cx="60" cy="60" r="${r}" fill="none" stroke="${col}" stroke-width="7"
        stroke-linecap="round"
        stroke-dasharray="${circ}"
        stroke-dashoffset="${offset}"
        style="transition:stroke-dashoffset 1.2s cubic-bezier(0.4,0,0.2,1);filter:drop-shadow(0 0 6px ${col})"
        transform="rotate(-90 60 60)"/>`;
    const val=document.getElementById('score-ring-val');
    const lbl=document.getElementById('score-ring-status');
    if (val) { val.textContent=pct; val.style.color=col; }
    if (lbl) { lbl.textContent=pct>=80?'SAFE':pct>=60?'WARNING':'DANGER'; lbl.style.color=col; }
  }

  /* ── Predictive Analytics ── */
  function buildPredictive() {
    const el=document.getElementById('predictiveChart');
    if (!el) return;
    destroy('predictiveChart');
    const hours=Array.from({length:24},(_,i)=>i+':00');
    const seed=window._netSecSeed||42;
    const actual=hours.map((_,i)=>Math.max(5,Math.round(40+Math.sin((i+seed)*0.5)*25+(i>17&&i<22?30:0))));
    const predicted=hours.map((v,i)=>i<18?null:Math.max(5,Math.round(actual[i]*(0.9+Math.random()*0.25))));
    const c=tc();
    save('predictiveChart', new Chart(el,{
      type:'line',
      data:{
        labels:hours,
        datasets:[
          {label:'Activité réelle',data:actual,borderColor:'#3b82f6',backgroundColor:'rgba(59,130,246,0.07)',borderWidth:2,fill:true,tension:0.4,pointRadius:2,spanGaps:false},
          {label:'Prédiction IA',data:predicted,borderColor:'#8b5cf6',backgroundColor:'rgba(139,92,246,0.06)',borderWidth:2,fill:true,tension:0.4,pointRadius:0,borderDash:[6,4],spanGaps:true},
        ]
      },
      options:{
        responsive:true,maintainAspectRatio:false,
        animation:{duration:700},
        interaction:{mode:'index',intersect:false},
        plugins:{
          legend:{display:true,labels:{color:c.tick,font:{size:10},boxWidth:10,usePointStyle:true}},
          tooltip:tooltipBase()
        },
        scales:Object.assign(axisBase(),{y:{...axisBase().y,beginAtZero:true}})
      }
    }));
  }

  /* ── Update all themes ── */
  function updateTheme() {
    const c=tc();
    Object.values(reg).forEach(chart=>{
      try {
        const scales=chart.config?.options?.scales;
        if (scales) Object.values(scales).forEach(s=>{
          if(s.grid)  s.grid.color=c.grid;
          if(s.ticks) s.ticks.color=c.tick;
        });
        const leg=chart.config?.options?.plugins?.legend;
        if(leg?.labels) leg.labels.color=c.tick;
        chart.update('none');
      } catch(e){}
    });
  }

  /* ── Monitoring update ── */
  function updateMonitoring() {
    fetch('/api/supervision')
      .then(r=>r.json())
      .then(data=>{
        const s=data.systeme;
        const set=(id,v)=>{const el=document.getElementById(id);if(el)el.textContent=v;};
        const bar=(id,pct,col)=>{const el=document.getElementById(id);if(!el)return;el.style.width=Math.min(100,pct)+'%';el.style.background=pct>85?'#ef4444':pct>65?'#f59e0b':col;};
        set('cpu-val',s.cpu+'%');bar('cpu-bar',s.cpu,'#3b82f6');
        set('ram-val',s.ram_pct+'%');bar('ram-bar',s.ram_pct,'#8b5cf6');
        set('ram-detail',s.ram_used+' MB / '+s.ram_total+' MB');
        set('disk-val',s.disk_pct+'%');bar('disk-bar',s.disk_pct,'#f59e0b');
        set('disk-detail',s.disk_used+' GB / '+s.disk_total+' GB');
        set('net-up','↑ '+s.bytes_sent+' KB');
        set('net-down','↓ '+s.bytes_recv+' KB');
        const st=document.getElementById('sys-statut');
        if(st){st.textContent=data.statut;st.className='badge '+(data.statut==='NORMAL'?'badge-safe':data.statut==='WARNING'?'badge-high':'badge-critical');}
        monHistory.cpu.push(s.cpu);monHistory.ram.push(s.ram_pct);
        if(monHistory.cpu.length>15)monHistory.cpu.shift();
        if(monHistory.ram.length>15)monHistory.ram.shift();
        buildMonitor(monHistory.cpu,monHistory.ram);
        // Score ring
        const scoreVal=document.getElementById('kpi-score');
        if(scoreVal) buildScoreRing(parseInt(scoreVal.textContent)||0);
      })
      .catch(()=>{});
  }

  /* ── Init ── */
  function init(cfg) {
    const c=cfg||{};
    window._netSecSeed=(c.nb_appareils||0)+(c.nb_alertes_high||0);
    sparkline('spark1',[5,7,8,6,9,10,11,c.nb_appareils||0],'#3b82f6');
    sparkline('spark2',[9,8,7,9,6,5,5,c.nb_alertes_high||0],'#ef4444');
    sparkline('spark3',[2,3,3,4,4,5,6,c.nb_bloques||0],'#8b5cf6');
    sparkline('spark4',[68,70,72,74,73,76,c.score_moyen||0,c.score_moyen||0],'#f59e0b');
    sparkline('spark5',[3,4,3,5,4,5,c.nb_scans||0,c.nb_scans||0],'#10b981');
    buildNetwork(7);
    buildThreat(c.critical||0,c.high||0,c.medium||0,c.low||0);
    buildSeverityTrend();
    buildScoreRing(c.score_moyen||0);
    for(let i=0;i<10;i++){monHistory.cpu.push(Math.round(8+Math.random()*20));monHistory.ram.push(Math.round(38+Math.random()*25));}
    buildMonitor(monHistory.cpu,monHistory.ram);
    updateMonitoring();
    setInterval(updateMonitoring,12000);
  }


  /* ── updateMonitoring depuis app.js ── */
  function updateMonitoringData(s) {
    const h = monHistory;
    h.cpu.push(s.cpu||0);
    h.ram.push(s.ram_pct||0);
    if(h.cpu.length>15) h.cpu.shift();
    if(h.ram.length>15) h.ram.shift();
    buildMonitor(h.cpu, h.ram);
    buildScoreRing(s.score||0);
  }
  return {
    init, updateTheme, updateMonitoring: updateMonitoringData, buildNetwork, buildThreat,
    buildSeverityTrend, buildTopProtocols, buildTopPorts,
    buildMonitor, buildScoreRing, buildPredictive,
    updateMonitoring
  };
})();

window.Charts=Charts;
window.updateNetworkChart=(days)=>Charts.buildNetwork(days);
