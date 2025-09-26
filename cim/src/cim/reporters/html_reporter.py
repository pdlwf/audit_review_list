from __future__ import annotations

import json
from pathlib import Path
from typing import Dict


def build_html_report(output_path: Path, report: Dict[str, object]) -> None:
    data_json = json.dumps(report)
    html_template = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Change Impact Map</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 0; display: flex; height: 100vh; color: #1a1a1a; }
    #sidebar { width: 320px; border-right: 1px solid #ddd; padding: 16px; overflow-y: auto; }
    #graph-container { flex: 1; position: relative; }
    #graph { width: 100%; height: 100%; }
    label { display: block; margin-top: 12px; font-weight: bold; }
    select, button { width: 100%; padding: 6px; margin-top: 6px; }
    #details { position: absolute; bottom: 16px; left: 16px; background: rgba(255,255,255,0.9); border: 1px solid #ccc; padding: 8px; max-width: 360px; font-size: 12px; white-space: pre-wrap; display: none; }
  </style>
</head>
<body>
  <div id="sidebar">
    <h2>图谱筛选</h2>
    <label for="langFilter">语言</label>
    <select id="langFilter"></select>
    <label for="dirFilter">顶层目录</label>
    <select id="dirFilter"></select>
    <label for="tagFilter">标签</label>
    <select id="tagFilter"></select>
    <button id="exportButton">导出当前视图 JSON</button>
    <p style="margin-top:16px;font-size:12px;line-height:1.5;">提示：点击节点可查看详情。节点颜色表示类型（文件、符号、资源、规则）。大小受中心性影响。</p>
  </div>
  <div id="graph-container">
    <canvas id="graph"></canvas>
    <div id="details"></div>
  </div>
  <script id="impact-data" type="application/json">__DATA_JSON__</script>
  <script>
    const DATA = JSON.parse(document.getElementById('impact-data').textContent);
    const canvas = document.getElementById('graph');
    const ctx = canvas.getContext('2d');
    const details = document.getElementById('details');
    const langFilter = document.getElementById('langFilter');
    const dirFilter = document.getElementById('dirFilter');
    const tagFilter = document.getElementById('tagFilter');
    const exportButton = document.getElementById('exportButton');

    let nodes = DATA.nodes || [];
    let edges = DATA.edges || [];
    let metrics = {};
    nodes.forEach(node => {
      metrics[node.id] = {
        inDegree: node.inDegree || 0,
        outDegree: node.outDegree || 0,
        centrality: node.centrality || 0,
      };
    });

    function resize() {
      canvas.width = canvas.clientWidth;
      canvas.height = canvas.clientHeight;
      draw();
    }
    window.addEventListener('resize', resize);

    function unique(values) {
      return Array.from(new Set(values.filter(Boolean))).sort();
    }

    function topDir(path) {
      if (!path) return 'global';
      return path.split('/')[0];
    }

    function collectOptions() {
      const langs = unique(nodes.map(node => node.lang));
      const dirs = unique(nodes.map(node => topDir(node.path)));
      const tags = unique(nodes.flatMap(node => node.tags || []));
      const populate = (select, items) => {
        select.innerHTML = '';
        const allOption = document.createElement('option');
        allOption.value = '';
        allOption.textContent = 'ALL';
        select.appendChild(allOption);
        items.forEach(item => {
          const opt = document.createElement('option');
          opt.value = item;
          opt.textContent = item;
          select.appendChild(opt);
        });
      };
      populate(langFilter, langs);
      populate(dirFilter, dirs);
      populate(tagFilter, tags);
    }

    function filteredNodes() {
      const lang = langFilter.value;
      const dir = dirFilter.value;
      const tag = tagFilter.value;
      return nodes.filter(node => {
        const langOk = !lang || node.lang === lang;
        const dirOk = !dir || topDir(node.path) === dir;
        const tagOk = !tag || (node.tags || []).includes(tag);
        return langOk && dirOk && tagOk;
      });
    }

    function filteredEdges(activeNodes) {
      const allowed = new Set(activeNodes.map(node => node.id));
      return edges.filter(edge => allowed.has(edge.from) && allowed.has(edge.to));
    }

    function createLayout(activeNodes) {
      const positions = new Map();
      const width = canvas.width;
      const height = canvas.height;
      const radius = Math.min(width, height) / 2 - 60;
      const cx = width / 2;
      const cy = height / 2;
      const count = Math.max(activeNodes.length, 1);
      activeNodes.forEach((node, index) => {
        const angle = (2 * Math.PI * index) / count;
        const strength = Math.min(1.5, Math.max(0.5, (metrics[node.id]?.centrality || 0) * 20 + 0.5));
        const nodeRadius = strength * 12;
        const r = radius * (0.8 + (metrics[node.id]?.centrality || 0));
        positions.set(node.id, {
          x: cx + r * Math.cos(angle),
          y: cy + r * Math.sin(angle),
          size: nodeRadius,
        });
      });
      return positions;
    }

    function colorFor(node) {
      switch (node.type) {
        case 'file': return '#3b82f6';
        case 'symbol': return '#10b981';
        case 'resource': return '#f97316';
        case 'pattern': return '#8b5cf6';
        default: return '#64748b';
      }
    }

    function draw() {
      const activeNodes = filteredNodes();
      const activeEdges = filteredEdges(activeNodes);
      const positions = createLayout(activeNodes);
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      ctx.save();
      ctx.translate(0.5, 0.5);
      ctx.strokeStyle = '#d1d5db';
      ctx.globalAlpha = 0.8;
      activeEdges.forEach(edge => {
        const from = positions.get(edge.from);
        const to = positions.get(edge.to);
        if (!from || !to) return;
        ctx.lineWidth = edge.strength === 'strong' ? 2 : 1;
        ctx.beginPath();
        ctx.moveTo(from.x, from.y);
        ctx.lineTo(to.x, to.y);
        ctx.stroke();
      });
      ctx.globalAlpha = 1;
      activeNodes.forEach(node => {
        const pos = positions.get(node.id);
        if (!pos) return;
        ctx.beginPath();
        ctx.fillStyle = colorFor(node);
        ctx.arc(pos.x, pos.y, pos.size, 0, Math.PI * 2);
        ctx.fill();
      });
      ctx.restore();
      canvas.__positions = positions;
      canvas.__activeNodes = activeNodes;
    }

    function findNodeAt(x, y) {
      const rect = canvas.getBoundingClientRect();
      const px = x - rect.left;
      const py = y - rect.top;
      const positions = canvas.__positions || new Map();
      const nodes = canvas.__activeNodes || [];
      for (const node of nodes) {
        const pos = positions.get(node.id);
        if (!pos) continue;
        const dx = px * (canvas.width / canvas.clientWidth) - pos.x;
        const dy = py * (canvas.height / canvas.clientHeight) - pos.y;
        if (Math.sqrt(dx * dx + dy * dy) <= pos.size) {
          return node;
        }
      }
      return null;
    }

    canvas.addEventListener('click', event => {
      const node = findNodeAt(event.clientX, event.clientY);
      if (!node) {
        details.style.display = 'none';
        return;
      }
      const info = { ...node };
      delete info['id'];
      details.textContent = 'Node: ' + node.id + '\n' + JSON.stringify(info, null, 2);
      details.style.display = 'block';
    });

    [langFilter, dirFilter, tagFilter].forEach(control => control.addEventListener('change', draw));

    exportButton.addEventListener('click', () => {
      const activeNodes = filteredNodes();
      const activeEdges = filteredEdges(activeNodes);
      const payload = JSON.stringify({
        nodes: activeNodes,
        edges: activeEdges,
      }, null, 2);
      const blob = new Blob([payload], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = 'impact_view.json';
      link.click();
      URL.revokeObjectURL(url);
    });

    collectOptions();
    resize();
    draw();
  </script>
</body>
</html>
"""
    html = html_template.replace("__DATA_JSON__", data_json)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")


__all__ = ["build_html_report"]
