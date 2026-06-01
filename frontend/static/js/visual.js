// TIMELINE
if (document.getElementById("timelineChart")) {
fetch("/api/timeline")
.then(r=>r.json())
.then(data=>{
    const labels = data.map(d => d.timestamp);
    const values = data.map((_,i)=> i+1);

    new Chart(document.getElementById("timelineChart"), {
        type: "line",
        data: {
            labels: labels,
            datasets: [{
                label: "Attacks",
                data: values
            }]
        }
    });
});
}


// HEATMAP
if (document.getElementById("heatmap")) {
fetch("/api/heatmap")
.then(r=>r.json())
.then(data=>{
    let html = "<table border='1'>";
    data.forEach(d=>{
        html += `<tr><td>${d.ip}</td><td>${d.count}</td></tr>`;
    });
    html += "</table>";
    document.getElementById("heatmap").innerHTML = html;
});
}


// NETWORK GRAPH
if (document.getElementById("network")) {
fetch("/api/graph")
.then(r=>r.json())
.then(data=>{
    const nodes = new vis.DataSet(data.nodes);
    const edges = new vis.DataSet(data.edges);

    new vis.Network(
        document.getElementById("network"),
        {nodes:nodes, edges:edges},
        {}
    );
});
}


// ATTACK FLOW
if (document.getElementById("attackFlow")) {
fetch("/api/attack-flow")
.then(r=>r.json())
.then(data=>{
    let html = "<ul>";
    data.forEach(d=>{
        html += `<li>${d.time} : ${d.src} → ${d.dst} (${d.type})</li>`;
    });
    html += "</ul>";
    document.getElementById("attackFlow").innerHTML = html;
});
}
