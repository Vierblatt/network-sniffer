"use strict";
var isCapturing = false;
var selectedRow = null;

function getEl(id) { return document.getElementById(id); }

async function apiPost(url) {
    try {
        var res = await fetch(url, { method: "POST" });
        return res.json();
    } catch (e) {
        return { error: "请求失败: " + e.message };
    }
}
async function apiGet(url) {
    try {
        var res = await fetch(url);
        return res.json();
    } catch (e) {
        return { error: "请求失败: " + e.message };
    }
}

// 页面加载时自动加载接口列表
window.addEventListener("DOMContentLoaded", function() {
    refreshInterfaces();
});

async function refreshInterfaces() {
    var data = await apiGet("/api/interfaces");
    var sel = getEl("interfaceSelect");
    if (data.error) {
        sel.innerHTML = '<option value="">' + data.error + '</option>';
        return;
    }
    sel.innerHTML = data.map(function(v) { return '<option value="' + v + '">' + v + '</option>'; }).join("");
    getEl("emptyState").innerHTML = '选择接口并点击"开始捕获"查看数据包';
}

async function startCapture() {
    var iface = getEl("interfaceSelect").value;
    if (!iface || iface.indexOf("无可用") >= 0 || iface.indexOf("(") === 0) {
        showError("请选择有效的网络接口");
        return;
    }
    var data = await apiPost("/api/start?iface=" + encodeURIComponent(iface));
    if (data.error) { showError(data.error); return; }
    isCapturing = true;
    getEl("startBtn").style.display = "none";
    getEl("stopBtn").style.display = "inline-flex";
    getEl("interfaceSelect").disabled = true;
    getEl("emptyState").innerHTML = '<div style="padding:40px;text-align:center;color:#999">正在捕获中...</div>';
    getEl("packetBody").innerHTML = "";
    getEl("errorMsg").style.display = "none";
    getEl("statusBar").textContent = "▶ 正在捕获数据包... 接口: " + iface;
    pollData();
}

function showError(msg) {
    var el = getEl("errorMsg");
    el.textContent = "⚠ " + msg;
    el.style.display = "inline";
    setTimeout(function() { el.style.display = "none"; }, 5000);
}

async function stopCapture() {
    await apiPost("/api/stop");
    isCapturing = false;
    pollRunning = false;
    getEl("startBtn").style.display = "inline-flex";
    getEl("stopBtn").style.display = "none";
    getEl("interfaceSelect").disabled = false;
    if (pollTimer) { clearTimeout(pollTimer); pollTimer = null; }
    getEl("statusBar").textContent = "⏹ 已停止捕获";
}

async function clearData() {
    await apiPost("/api/clear");
    getEl("packetBody").innerHTML = "";
    getEl("emptyState").style.display = "";
    getEl("emptyState").innerHTML = '选择接口并点击"开始捕获"查看数据包';
    getEl("packetCount").textContent = "0 个";
    updateStats({ totalPackets: 0, tcpCount: 0, udpCount: 0, icmpCount: 0, arpCount: 0, otherCount: 0, rate: "0", elapsed: "0s" });
    getEl("detailContent").innerHTML = '<div style="padding:20px;text-align:center;color:#999">点击数据包查看详情</div>';
}

var pollTimer = null;
var pollRunning = false;
function pollData() {
    if (!isCapturing || pollRunning) return;
    pollRunning = true;
    Promise.all([
        apiGet("/api/packets"),
        apiGet("/api/stats")
    ]).then(function(results) {
        var packets = results[0], stats = results[1];
        if (!packets.error) renderPackets(packets);
        if (!stats.error) updateStats(stats);
    }).finally(function() {
        pollRunning = false;
        if (isCapturing) pollTimer = setTimeout(pollData, 500);
    });
}

function getProtocolClass(proto) {
    switch (proto) {
        case "TCP": return "background:#e3f2fd;color:#1565c0";
        case "UDP": return "background:#e8f5e9;color:#2e7d32";
        case "ICMP": return "background:#fff3e0;color:#e65100";
        case "ARP": return "background:#f3e5f5;color:#7b1fa2";
        default: return "background:#f5f5f5;color:#616161";
    }
}

function renderPackets(packets) {
    var tbody = getEl("packetBody");
    var empty = getEl("emptyState");
    if (!packets || packets.length === 0) {
        if (isCapturing) empty.innerHTML = '<div style="padding:40px;text-align:center;color:#999">等待数据包...</div>';
        return;
    }
    empty.style.display = "none";
    var currentCount = tbody.children.length;
    var newPackets = packets.slice(currentCount);
    for (var i = 0; i < newPackets.length; i++) {
        var p = newPackets[i];
        var tr = document.createElement("tr");
        tr.style.cursor = "pointer";
        tr.onclick = (function(pkt, row) {
            return function() { showDetail(pkt, row); };
        })(p, tr);
        var protoStyle = getProtocolClass(p.protocol);
        tr.innerHTML =
            "<td>" + p.seq + "</td>" +
            "<td style=\"color:#888;font-size:11px\">" + (p.time || "") + "</td>" +
            "<td>" + (p.srcIP || "-") + "</td>" +
            "<td>" + (p.dstIP || "-") + "</td>" +
            "<td><span style=\"padding:1px 8px;border-radius:10px;font-size:11px;font-weight:600;" + protoStyle + "\">" + (p.protocol || "-") + "</span></td>" +
            "<td>" + (p.srcPort || "-") + "</td>" +
            "<td>" + (p.dstPort || "-") + "</td>" +
            "<td>" + (p.length || "0") + "</td>";
        tbody.appendChild(tr);
    }
    getEl("packetCount").textContent = packets.length + " 个";
    // Auto-scroll only if user is near the bottom
    var wrap = tbody.parentElement;
    if (wrap) {
        var nearBottom = wrap.scrollHeight - wrap.scrollTop - wrap.clientHeight < 60;
        if (nearBottom) wrap.scrollTop = wrap.scrollHeight;
    }
}

function showDetail(p, row) {
    if (selectedRow) selectedRow.style.background = "";
    if (row) { row.style.background = "#e3f0ff"; selectedRow = row; }
    var html = "";
    html += "══ 数据包 #" + p.seq + " ══\n";
    html += "时间: " + (p.time || "-") + "\n";
    html += "长度: " + (p.length || "0") + " 字节\n\n";
    html += "── 链路层 ──\n";
    html += "源MAC: " + (p.srcMAC || "-") + "\n";
    html += "目的MAC: " + (p.dstMAC || "-") + "\n\n";
    html += "── 网络层 ──\n";
    html += "源IP: " + (p.srcIP || "-") + "\n";
    html += "目的IP: " + (p.dstIP || "-") + "\n";
    html += "协议: " + (p.protocol || "-") + "\n";
    if (p.srcPort && p.srcPort !== "-" && p.dstPort && p.dstPort !== "-") {
        html += "\n── 传输层 ──\n";
        html += "源端口: " + p.srcPort + "\n";
        html += "目的端口: " + p.dstPort + "\n";
    }
    if (p.detail) {
        html += "\n── 详细信息 ──\n";
        var parts = p.detail.split(" | ");
        for (var j = 0; j < parts.length; j++) {
            if (parts[j].trim()) html += parts[j].trim() + "\n";
        }
    }
    html += "══════════════════════════════════";
    getEl("detailContent").innerHTML = '<pre style="margin:0;font-family:Consolas,monospace;font-size:13px;line-height:1.6;white-space:pre-wrap">' + html + "</pre>";
}

function updateStats(s) {
    if (!s) return;
    getEl("statTotal").textContent = s.totalPackets || 0;
    getEl("statTCP").textContent = s.tcpCount || 0;
    getEl("statUDP").textContent = s.udpCount || 0;
    getEl("statICMP").textContent = s.icmpCount || 0;
    getEl("statARP").textContent = s.arpCount || 0;
    getEl("statOther").textContent = s.otherCount || 0;
    getEl("statRate").textContent = (s.rate || "0") + " 包/秒";
    getEl("statElapsed").textContent = s.elapsed || "0s";
}

// 非捕获状态定时刷新统计
setInterval(function() {
    if (!isCapturing) apiGet("/api/stats").then(function(data) {
        if (data && !data.error) updateStats(data);
    });
}, 2000);
