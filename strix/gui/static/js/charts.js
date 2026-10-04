/**
 * iqAudi360 - Lightweight SVG Chart Renderer
 */

function renderSeverityDonut(containerId, counts) {
  const container = document.getElementById(containerId);
  if (!container) return;

  const total = counts.total || 0;
  if (total === 0) {
    container.innerHTML = `
      <div style="text-align:center; padding: 30px 10px; color: #64748b;">
        <div style="font-size: 24px; margin-bottom: 6px;">🛡️</div>
        <div style="font-size: 13px; font-weight: 600; color: #94a3b8;">0 Findings Detected</div>
        <div style="font-size: 11px;">Scanned surfaces showed no vulnerabilities.</div>
      </div>
    `;
    return;
  }

  const items = [
    { label: "Critical", count: counts.critical || 0, color: "#ef4444" },
    { label: "High", count: counts.high || 0, color: "#f97316" },
    { label: "Medium", count: counts.medium || 0, color: "#eab308" },
    { label: "Low", count: counts.low || 0, color: "#06b6d4" },
  ];

  const size = 180;
  const strokeWidth = 22;
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const center = size / 2;

  let accumulatedPercent = 0;
  let paths = "";

  items.forEach((item) => {
    if (item.count <= 0) return;
    const percent = item.count / total;
    const strokeDasharray = `${percent * circumference} ${circumference}`;
    const strokeDashoffset = -(accumulatedPercent * circumference);

    paths += `
      <circle
        cx="${center}"
        cy="${center}"
        r="${radius}"
        fill="transparent"
        stroke="${item.color}"
        stroke-width="${strokeWidth}"
        stroke-dasharray="${strokeDasharray}"
        stroke-dashoffset="${strokeDashoffset}"
        stroke-linecap="round"
        style="transition: stroke-dasharray 0.5s ease;"
      />
    `;
    accumulatedPercent += percent;
  });

  const svg = `
    <div style="display: flex; align-items: center; justify-content: space-around; flex-wrap: wrap; gap: 20px;">
      <div style="position: relative; width: ${size}px; height: ${size}px;">
        <svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" style="transform: rotate(-90deg);">
          <circle
            cx="${center}"
            cy="${center}"
            r="${radius}"
            fill="transparent"
            stroke="rgba(255, 255, 255, 0.05)"
            stroke-width="${strokeWidth}"
          />
          ${paths}
        </svg>
        <div style="position: absolute; top:0; left:0; width:100%; height:100%; display:flex; flex-direction:column; align-items:center; justify-content:center; pointer-events:none;">
          <span style="font-size: 26px; font-weight: 800; color: #fff;">${total}</span>
          <span style="font-size: 10px; text-transform: uppercase; color: #64748b; font-weight: 700;">Findings</span>
        </div>
      </div>
      <div style="display: flex; flex-direction: column; gap: 8px; min-width: 130px;">
        ${items.map(i => `
          <div style="display: flex; align-items: center; justify-content: space-between; font-size: 12px;">
            <div style="display: flex; align-items: center; gap: 8px;">
              <span style="width: 10px; height: 10px; border-radius: 50%; background-color: ${i.color}; display: inline-block;"></span>
              <span style="color: #94a3b8;">${i.label}</span>
            </div>
            <span style="font-weight: 700; color: #fff;">${i.count}</span>
          </div>
        `).join("")}
      </div>
    </div>
  `;

  container.innerHTML = svg;
}
