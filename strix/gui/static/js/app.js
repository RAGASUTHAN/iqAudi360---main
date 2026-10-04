/**
 * iqAudi360 - Global Web Application Utilities
 */

document.addEventListener("DOMContentLoaded", () => {
  // Mobile Sidebar Toggle
  const menuBtn = document.getElementById("mobileMenuBtn");
  const sidebar = document.getElementById("sidebar");
  if (menuBtn && sidebar) {
    menuBtn.addEventListener("click", () => {
      sidebar.classList.toggle("mobile-open");
    });
  }

  // Close modals when clicking overlay
  const modals = document.querySelectorAll(".modal-overlay");
  modals.forEach((modal) => {
    modal.addEventListener("click", (e) => {
      if (e.target === modal) {
        modal.classList.remove("open");
      }
    });
  });
});

/**
 * Toast Notification Helper
 */
function showToast(message, type = "info") {
  let container = document.getElementById("toastContainer");
  if (!container) {
    container = document.createElement("div");
    container.id = "toastContainer";
    container.className = "toast-container";
    document.body.appendChild(container);
  }

  const toast = document.createElement("div");
  toast.className = `toast toast-${type}`;
  toast.innerText = message;

  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transition = "opacity 0.3s ease";
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

/**
 * Copy to Clipboard Helper
 */
function copyToClipboard(text, successMsg = "Copied to clipboard!") {
  if (navigator.clipboard) {
    navigator.clipboard.writeText(text).then(() => {
      showToast(successMsg, "success");
    }).catch(() => {
      showToast("Failed to copy", "error");
    });
  }
}

/**
 * Open Finding Details Modal
 */
function openFindingModal(finding) {
  const modal = document.getElementById("findingDetailModal");
  if (!modal) return;

  document.getElementById("modalFindingTitle").innerText = finding.title || "Vulnerability Detail";
  document.getElementById("modalFindingId").innerText = finding.id || "";
  document.getElementById("modalFindingSev").className = `badge badge-${finding.severity}`;
  document.getElementById("modalFindingSev").innerText = (finding.severity || "medium").toUpperCase();
  document.getElementById("modalFindingCwe").innerText = finding.cwe || "N/A";
  document.getElementById("modalFindingTarget").innerText = finding.target || "N/A";
  document.getElementById("modalFindingDesc").innerText = finding.description || "No description provided.";
  
  const recEl = document.getElementById("modalFindingRec");
  if (recEl) {
    recEl.innerText = finding.recommendation || "No specific recommendation provided.";
  }

  const eviEl = document.getElementById("modalFindingEvidence");
  const eviContainer = document.getElementById("modalFindingEvidenceContainer");
  if (eviEl && eviContainer) {
    if (finding.evidence) {
      eviEl.innerText = finding.evidence;
      eviContainer.style.display = "block";
    } else {
      eviContainer.style.display = "none";
    }
  }

  modal.classList.add("open");
}

function closeFindingModal() {
  const modal = document.getElementById("findingDetailModal");
  if (modal) modal.classList.remove("open");
}

function toggleUserDropdown() {
  const menu = document.getElementById("userDropdownMenu");
  if (menu) {
    menu.style.display = menu.style.display === "block" ? "none" : "block";
  }
}

document.addEventListener("click", (e) => {
  const container = document.querySelector(".user-menu-container");
  const menu = document.getElementById("userDropdownMenu");
  if (container && menu && !container.contains(e.target)) {
    menu.style.display = "none";
  }
});

async function handleTenantSwitch(tenantId) {
  if (!tenantId) return;
  try {
    const res = await fetch("/api/auth/switch-tenant", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ tenant_id: tenantId })
    });
    if (res.ok) {
      window.location.reload();
    } else {
      const d = await res.json();
      showToast(d.message || "Failed to switch organization", "error");
    }
  } catch (err) {
    showToast("Network error switching organization", "error");
  }
}
