async function postJSON(path, data) {
  const response = await fetch(path, {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(data)});
  const body = await response.json();
  if (!response.ok) throw new Error(body.error || "Request failed.");
  return body;
}
function showResult(id, html, error=false) {
  const box=document.getElementById(id); box.classList.remove("hidden"); box.classList.toggle("error",error); box.innerHTML=html;
}
function safe(value) {
  return String(value ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}
function resultHTML(data) {
  let html=`<strong>${safe(data.status)}</strong><br>Risk: <b class="risk ${safe(data.risk)}">${safe(data.risk)}</b><br>${safe(data.summary)}`;
  if(data.findings) html+="<ul>"+data.findings.map(x=>`<li>${safe(x)}</li>`).join("")+"</ul>";
  if(data.tls) html+=`<br><b>TLS:</b> ${safe(data.tls)}`;
  if(data.breaches?.length) html+="<ul>"+data.breaches.map(b=>`<li><b>${safe(b.name)}</b> — ${safe(b.date || "date unknown")} (${safe(b.domain || "domain unknown")})</li>`).join("")+"</ul>";
  if(data.important_limit) html+=`<br><small>${safe(data.important_limit)}</small>`;
  return html;
}
document.getElementById("emailForm").addEventListener("submit", async e=>{
  e.preventDefault(); const button=e.currentTarget.querySelector("button"); button.disabled=true; button.textContent="CHECKING...";
  try {const data=await postJSON("/api/check-email",{email:document.getElementById("email").value});showResult("emailResult",resultHTML(data));}
  catch(err){showResult("emailResult",safe(err.message),true);}
  finally{button.disabled=false;button.innerHTML='CHECK EMAIL <span>→</span>';loadDashboard();}
});
document.getElementById("websiteForm").addEventListener("submit", async e=>{
  e.preventDefault(); const button=e.currentTarget.querySelector("button"); button.disabled=true; button.textContent="SCANNING...";
  try {const data=await postJSON("/api/check-website",{url:document.getElementById("url").value});showResult("websiteResult",resultHTML(data));}
  catch(err){showResult("websiteResult",safe(err.message),true);}
  finally{button.disabled=false;button.innerHTML='SCAN URL <span>→</span>';loadDashboard();}
});
async function loadDashboard(){
  const res=await fetch("/api/stats");const data=await res.json();
  document.getElementById("totalScans").textContent=data.total;
  document.getElementById("websiteScans").textContent=data.websites;
  document.getElementById("emailScans").textContent=data.emails;
  const body=document.getElementById("historyBody");
  body.innerHTML=data.recent.length?data.recent.map(r=>`<tr><td>${safe(r.scan_type)}</td><td>${safe(r.target)}</td><td>${safe(r.status)}</td><td class="risk ${safe(r.risk)}">${safe(r.risk)}</td><td>${safe(new Date(r.created_at).toLocaleString())}</td></tr>`).join(""):'<tr><td colspan="5">No scans yet. Run your first check above.</td></tr>';
}
document.getElementById("refresh").addEventListener("click",loadDashboard);
loadDashboard();
// Password Generator
let generatedPassword = "";

document.getElementById("passwordForm").addEventListener("submit", async e => {
    e.preventDefault();

    const button = e.currentTarget.querySelector("button[type='submit']");
    button.disabled = true;
    button.textContent = "GENERATING...";

    const data = {
        length: Number(document.getElementById("passwordLength").value),
        uppercase: document.getElementById("uppercase").checked,
        lowercase: document.getElementById("lowercase").checked,
        numbers: document.getElementById("numbers").checked,
        symbols: document.getElementById("symbols").checked
    };

    try {
        const result = await postJSON("/api/generate-password", data);

        generatedPassword = result.password;

        showResult(
            "passwordResult",
            `<strong>Your Strong Password:</strong><br>
            <code>${safe(result.password)}</code><br>
            Strength: <b class="risk Low">Strong</b>`
        );

        document.getElementById("copyPassword").classList.remove("hidden");

    } catch (err) {
        showResult("passwordResult", safe(err.message), true);
    } finally {
        button.disabled = false;
        button.textContent = "GENERATE PASSWORD →";
    }
});

// Copy Password
document.getElementById("copyPassword").addEventListener("click", async () => {
    if (!generatedPassword) return;

    try {
        await navigator.clipboard.writeText(generatedPassword);
        document.getElementById("copyPassword").textContent = "COPIED!";
    } catch (err) {
        showResult("passwordResult", "Could not copy automatically. Please select and copy the password.", true);
    }
});
// Live Password Strength Checker
document.getElementById("checkPassword").addEventListener("input", function () {
    const password = this.value;
    const result = document.getElementById("strengthResult");

    result.className = "result strength-result";

    if (password.length === 0) {
        result.classList.add("hidden");
        return;
    }

    let score = 0;

    if (password.length >= 8) score++;
    if (/[A-Z]/.test(password)) score++;
    if (/[a-z]/.test(password)) score++;
    if (/[0-9]/.test(password)) score++;
    if (/[^A-Za-z0-9]/.test(password)) score++;

    let strength;
    let colorClass;

    if (score <= 2) {
        strength = "Weak";
        colorClass = "weak";
    } else if (score === 3) {
        strength = "Medium";
        colorClass = "medium";
    } else if (score === 4) {
        strength = "Strong";
        colorClass = "strong";
    } else {
        strength = "Very Strong";
        colorClass = "very-strong";
    }

    result.classList.add(colorClass);
    result.innerHTML = `Password Strength: ${strength}`;
});
// Show or hide password
const toggleButton = document.getElementById("toggleCheckPassword");

toggleButton.addEventListener("click", function () {
    const password = document.getElementById("checkPassword");

    if (password.type === "password") {
        password.type = "text";
        this.textContent = "🙈";
    } else {
        password.type = "password";
        this.textContent = "👁";
    }
});
// IP Address Threat Checker
document.getElementById("ipForm").addEventListener("submit", async function (e) {
    e.preventDefault();

    const ip = document.getElementById("ipAddress").value.trim();
    const result = document.getElementById("ipResult");

    result.classList.remove("hidden");
    result.textContent = "Checking IP address...";

    try {
        const response = await fetch("/api/check-ip", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ ip: ip })
        });

        const data = await response.json();

        result.replaceChildren();

        if (!response.ok) {
            result.textContent = data.error || "IP lookup failed.";
            return;
        }

        const heading = document.createElement("h4");
        heading.textContent = "IP Lookup Results";
        result.appendChild(heading);

        const details = [
            ["IP Address", data.ip],
            ["Country", data.country],
            ["Region", data.region],
            ["City", data.city],
            ["ISP", data.isp],
            ["Organization", data.organization],
            ["Latitude", data.latitude],
            ["Longitude", data.longitude]
        ];

        details.forEach(([label, value]) => {
            const p = document.createElement("p");
            p.textContent = `${label}: ${value ?? "Not available"}`;
            result.appendChild(p);
        });
        // Add IP location to map
if (data.latitude != null && data.longitude != null) {

    if (window.ipMarker) {
        threatMap.removeLayer(window.ipMarker);
    }

    window.ipMarker = L.marker([
        data.latitude,
        data.longitude
    ]).addTo(threatMap);

    window.ipMarker.bindPopup(
        `Approximate IP Location: ${data.city}, ${data.country}`
    ).openPopup();

    threatMap.setView([
        data.latitude,
        data.longitude
    ], 6);
}

    } catch (error) {
        result.textContent = "Unable to connect to the server.";
    }
});
// Threat Intelligence Map
const threatMap = L.map("map").setView([20, 0], 2);

L.tileLayer("https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}", {
    attribution: "Tiles &copy; Esri",
    maxZoom: 16
}).addTo(threatMap);
// Dashboard Risk Statistics
async function loadRiskStats() {
    try {
        const response = await fetch("/api/dashboard-stats");
        const data = await response.json();

        if (!response.ok) {
            throw new Error("Unable to load dashboard statistics.");
        }

        document.getElementById("highRiskScans").textContent = data.high_risk;
        document.getElementById("mediumRiskScans").textContent = data.medium_risk;
        document.getElementById("lowRiskScans").textContent = data.low_risk;

    } catch (error) {
        console.error("Dashboard statistics error:", error);
    }
}

loadRiskStats();

setInterval(loadRiskStats, 30000);
// Threat Activity Chart
let threatChart;

async function loadThreatChart() {
    try {
        const response = await fetch("/api/dashboard-stats");
        const data = await response.json();

        if (!response.ok) {
            throw new Error("Unable to load chart data.");
        }

        const chartData = {
            labels: ["High Risk", "Medium Risk", "Low Risk"],
            datasets: [{
                data: [
                    data.high_risk,
                    data.medium_risk,
                    data.low_risk
                ],
                backgroundColor: [
                    "#ff4757",
                    "#ffa502",
                    "#2ed573"
                ],
                borderWidth: 2
            }]
        };

        if (threatChart) {
            threatChart.data = chartData;
            threatChart.update();
        } else {
            threatChart = new Chart(
                document.getElementById("threatChart"),
                {
                    type: "doughnut",
                    data: chartData,
                    options: {
    responsive: true,
    maintainAspectRatio: true,
    cutout: "72%",
    animation: {
        animateScale: true,
        animateRotate: true,
        duration: 1200
    },
    plugins: {
        legend: {
            position: "bottom",
            labels: {
                color: "#b7c9bd",
                padding: 25,
                usePointStyle: true,
                pointStyle: "circle",
                font: {
                    size: 12
                }
            }
        },
        tooltip: {
            backgroundColor: "#101b14",
            titleColor: "#00ff88",
            bodyColor: "#ffffff",
            borderColor: "#00ff88",
            borderWidth: 1,
            padding: 12
        }
    }
}
                }
            );
        }

    } catch (error) {
        console.error("Threat chart error:", error);
    }
}

loadThreatChart();

setInterval(loadThreatChart, 30000);
// Clear Scan History
document.getElementById("clearHistory").addEventListener("click", async function () {

    const confirmClear = confirm(
        "Are you sure you want to delete all scan history?"
    );

    if (!confirmClear) return;

    const button = this;
    button.disabled = true;
    button.textContent = "CLEARING...";

    try {
        const response = await fetch("/api/clear-history", {
            method: "DELETE"
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Unable to clear history.");
        }

        alert(data.message);

        loadDashboard();

    } catch (error) {
        alert(error.message);
    } finally {
        button.disabled = false;
        button.textContent = "CLEAR HISTORY";
    }
});
    