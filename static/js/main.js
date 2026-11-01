// OMNITRIX // Galvan Level-20 Shared Telemetry Utilities & Single-Page Platform Switcher

document.addEventListener("DOMContentLoaded", () => {
  // Mobile sidebar toggle
  const toggle = document.getElementById("menu-toggle");
  const sidebar = document.getElementById("sidebar");
  if (toggle && sidebar) {
    toggle.addEventListener("click", () => sidebar.classList.toggle("open"));
    document.addEventListener("click", (e) => {
      if (!sidebar.contains(e.target) && !toggle.contains(e.target)) {
        sidebar.classList.remove("open");
      }
    });
  }

  // Keyboard shortcut listener: press '/' to focus scan input
  document.addEventListener("keydown", (e) => {
    const isInput = ["INPUT", "TEXTAREA", "SELECT"].includes(document.activeElement?.tagName);
    if (e.key === "/" && !isInput) {
      e.preventDefault();
      const phishSec = document.getElementById("section-phishguard");
      const isPhishVisible = phishSec && phishSec.style.display !== "none";
      const input = isPhishVisible ? document.getElementById("url-input") : document.getElementById("target-input");
      if (input) {
        input.focus();
        input.select();
      } else {
        window.location.href = "/#scan-form";
      }
    } else if (e.key === "Escape") {
      if (isInput) {
        document.activeElement.blur();
      }
    }
  });

  // Topbar quick scan button
  const topbarBtn = document.getElementById("topbar-quick-scan");
  if (topbarBtn) {
    topbarBtn.addEventListener("click", () => {
      const phishSec = document.getElementById("section-phishguard");
      const isPhishVisible = phishSec && phishSec.style.display !== "none";
      const input = isPhishVisible ? document.getElementById("url-input") : document.getElementById("target-input");
      if (input) {
        input.focus();
        input.scrollIntoView({ behavior: "smooth", block: "center" });
      } else {
        window.location.href = "/";
      }
    });
  }

  // Topbar switch buttons
  const btnCaemp = document.getElementById("tab-btn-caemp");
  const btnPhish = document.getElementById("tab-btn-phishguard");
  if (btnCaemp) {
    btnCaemp.addEventListener("click", (e) => {
      e.preventDefault();
      window.switchPlatformSection("caemp");
    });
  }
  if (btnPhish) {
    btnPhish.addEventListener("click", (e) => {
      e.preventDefault();
      window.switchPlatformSection("phishguard");
    });
  }

  // Sidebar links for sections and subviews
  const sideCaemp = document.getElementById("side-nav-caemp");
  const sideHistory = document.getElementById("side-nav-history");
  const sideReports = document.getElementById("side-nav-reports");
  const sidePhish = document.getElementById("side-nav-phishguard");
  const sidePhishHist = document.getElementById("side-nav-phish-history");

  if (sideCaemp) {
    sideCaemp.addEventListener("click", (e) => {
      if (document.getElementById("section-caemp")) {
        e.preventDefault();
        window.switchCaempSubview("overview");
      }
    });
  }
  if (sideHistory) {
    sideHistory.addEventListener("click", (e) => {
      if (document.getElementById("caemp-view-history")) {
        e.preventDefault();
        window.switchCaempSubview("history");
      }
    });
  }
  if (sideReports) {
    sideReports.addEventListener("click", (e) => {
      if (document.getElementById("caemp-view-reports")) {
        e.preventDefault();
        window.switchCaempSubview("reports");
      }
    });
  }
  if (sidePhish) {
    sidePhish.addEventListener("click", (e) => {
      if (document.getElementById("section-phishguard")) {
        e.preventDefault();
        window.switchPlatformSection("phishguard");
      }
    });
  }
  if (sidePhishHist) {
    sidePhishHist.addEventListener("click", (e) => {
      if (document.getElementById("section-phishguard")) {
        e.preventDefault();
        window.switchPlatformSection("phishguard");
        setTimeout(() => {
          const el = document.getElementById("url-history-section");
          if (el) el.scrollIntoView({ behavior: "smooth" });
        }, 120);
      }
    });
  }

  // Initial Section & Subview Determination on Page Load
  const caempSec = document.getElementById("section-caemp");
  const phishSec = document.getElementById("section-phishguard");

  if (caempSec && phishSec) {
    const hash = window.location.hash.toLowerCase();
    const saved = localStorage.getItem("active_platform_section");
    if (hash.includes("phishguard") || hash.includes("url") || (saved === "phishguard" && !hash.includes("caemp") && !hash.includes("history") && !hash.includes("reports") && !hash.includes("overview"))) {
      window.switchPlatformSection("phishguard", false);
    } else {
      window.switchPlatformSection("caemp", false);
      if (hash.includes("history")) {
        window.switchCaempSubview("history");
      } else if (hash.includes("reports")) {
        window.switchCaempSubview("reports");
      } else {
        const savedSubview = localStorage.getItem("active_caemp_subview") || "overview";
        window.switchCaempSubview(savedSubview);
      }
    }
  }
});

// =====================================================================
// SINGLE-PAGE PLATFORM SWITCHER (CAEMP <-> PHISHGUARD)
// =====================================================================
window.switchPlatformSection = function(section, allowRedirect = true) {
  const caempSec = document.getElementById("section-caemp");
  const phishSec = document.getElementById("section-phishguard");
  const tabCaemp = document.getElementById("tab-btn-caemp");
  const tabPhish = document.getElementById("tab-btn-phishguard");
  const sideCaemp = document.getElementById("side-nav-caemp");
  const sideHistory = document.getElementById("side-nav-history");
  const sideReports = document.getElementById("side-nav-reports");
  const sidePhish = document.getElementById("side-nav-phishguard");
  const sidePhishHist = document.getElementById("side-nav-phish-history");
  const crumbSection = document.getElementById("topbar-crumb-section");
  const crumbPage = document.getElementById("topbar-crumb-page");

  // If on a page other than root dashboard (e.g. /history, /reports, /scan/<uid>)
  if (!caempSec || !phishSec) {
    if (allowRedirect) {
      window.location.href = section === "phishguard" ? "/#phishguard" : "/";
    }
    return;
  }

  if (section === "phishguard") {
    caempSec.style.display = "none";
    caempSec.classList.remove("active");
    phishSec.style.display = "block";
    phishSec.classList.add("active");

    if (tabCaemp) tabCaemp.classList.remove("active");
    if (tabPhish) tabPhish.classList.add("active");

    if (sideCaemp) sideCaemp.classList.remove("active");
    if (sideHistory) sideHistory.classList.remove("active");
    if (sideReports) sideReports.classList.remove("active");
    if (sidePhish) sidePhish.classList.add("active");
    if (sidePhishHist) sidePhishHist.classList.remove("active");

    if (crumbSection) crumbSection.textContent = "PHISHGUARD //";
    if (crumbPage) crumbPage.textContent = "Live URL Inspector";

    localStorage.setItem("active_platform_section", "phishguard");
    try { window.history.replaceState(null, "", "#phishguard"); } catch(e) {}

    // Focus URL input for fast user action
    const urlInput = document.getElementById("url-input");
    if (urlInput) {
      setTimeout(() => urlInput.focus(), 100);
    }
  } else {
    phishSec.style.display = "none";
    phishSec.classList.remove("active");
    caempSec.style.display = "block";
    caempSec.classList.add("active");

    if (tabPhish) tabPhish.classList.remove("active");
    if (tabCaemp) tabCaemp.classList.add("active");

    if (sidePhish) sidePhish.classList.remove("active");
    if (sidePhishHist) sidePhishHist.classList.remove("active");

    localStorage.setItem("active_platform_section", "caemp");

    const savedSubview = localStorage.getItem("active_caemp_subview") || "overview";
    window.switchCaempSubview(savedSubview);

    const targetInput = document.getElementById("target-input");
    if (targetInput) {
      setTimeout(() => targetInput.focus(), 100);
    }
  }
};

// =====================================================================
// CAEMP SUBVIEW SWITCHER (Overview <-> Scan History <-> Reports)
// =====================================================================
window.switchCaempSubview = function(subview = "overview") {
  const caempSec = document.getElementById("section-caemp");
  const phishSec = document.getElementById("section-phishguard");
  const tabCaemp = document.getElementById("tab-btn-caemp");
  const tabPhish = document.getElementById("tab-btn-phishguard");

  // Ensure CAEMP parent container is visible
  if (phishSec && phishSec.style.display !== "none") {
    phishSec.style.display = "none";
    phishSec.classList.remove("active");
    if (caempSec) {
      caempSec.style.display = "block";
      caempSec.classList.add("active");
    }
    if (tabPhish) tabPhish.classList.remove("active");
    if (tabCaemp) tabCaemp.classList.add("active");
    localStorage.setItem("active_platform_section", "caemp");
  }

  const views = {
    overview: document.getElementById("caemp-view-overview"),
    history: document.getElementById("caemp-view-history"),
    reports: document.getElementById("caemp-view-reports"),
  };

  const btns = {
    overview: document.getElementById("btn-subnav-overview"),
    history: document.getElementById("btn-subnav-history"),
    reports: document.getElementById("btn-subnav-reports"),
  };

  const sideLinks = {
    overview: document.getElementById("side-nav-caemp"),
    history: document.getElementById("side-nav-history"),
    reports: document.getElementById("side-nav-reports"),
  };

  // If on standalone page, redirect to home with hash
  if (!views.overview && !views.history && !views.reports) {
    window.location.href = "/#" + subview;
    return;
  }

  // Toggle subviews
  Object.keys(views).forEach((key) => {
    if (views[key]) {
      if (key === subview) {
        views[key].style.display = "block";
        views[key].classList.add("active");
      } else {
        views[key].style.display = "none";
        views[key].classList.remove("active");
      }
    }
  });

  // Toggle subnav buttons
  Object.keys(btns).forEach((key) => {
    if (btns[key]) {
      btns[key].classList.toggle("active", key === subview);
    }
  });

  // Toggle sidebar links
  Object.keys(sideLinks).forEach((key) => {
    if (sideLinks[key]) {
      sideLinks[key].classList.toggle("active", key === subview);
    }
  });

  const sidePhish = document.getElementById("side-nav-phishguard");
  const sidePhishHist = document.getElementById("side-nav-phish-history");
  if (sidePhish) sidePhish.classList.remove("active");
  if (sidePhishHist) sidePhishHist.classList.remove("active");

  // Update Breadcrumbs
  const crumbSection = document.getElementById("topbar-crumb-section");
  const crumbPage = document.getElementById("topbar-crumb-page");
  if (crumbSection) crumbSection.textContent = "CAEMP //";
  if (crumbPage) {
    if (subview === "history") crumbPage.textContent = "Scan History Archive";
    else if (subview === "reports") crumbPage.textContent = "Security Reports";
    else crumbPage.textContent = "Executive Dashboard";
  }

  // Update hash
  try {
    window.history.replaceState(null, "", "#" + subview);
  } catch(e) {}

  localStorage.setItem("active_caemp_subview", subview);

  // Resize charts if returning to overview
  if (subview === "overview" && window.Chart && Chart.instances) {
    setTimeout(() => {
      Object.values(Chart.instances).forEach((c) => {
        try { c.resize(); } catch(e) {}
      });
    }, 60);
  }
};

// Toast notification helper
window.CAEMP_TOAST = function (message) {
  const toast = document.getElementById("caemp-toast");
  if (!toast) return;
  toast.textContent = message;
  toast.classList.add("show");
  clearTimeout(window.__toastTimeout);
  window.__toastTimeout = setTimeout(() => {
    toast.classList.remove("show");
  }, 2400);
};

// Copy-to-clipboard helper
window.CAEMP_COPY = function (text, message = "Target node copied") {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(() => {
      window.CAEMP_TOAST(message);
    }).catch(() => {
      fallbackCopy(text, message);
    });
  } else {
    fallbackCopy(text, message);
  }
};

function fallbackCopy(text, message) {
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.style.position = "fixed";
  ta.style.opacity = "0";
  document.body.appendChild(ta);
  ta.select();
  try {
    document.execCommand("copy");
    window.CAEMP_TOAST(message);
  } catch (err) {
    window.CAEMP_TOAST("Failed to copy");
  }
  document.body.removeChild(ta);
}

// Omnitrix Galvanic Severity Palette
window.CAEMP_SEVERITY_COLORS = {
  Critical: "#FF1744",
  High: "#FFAB00",
  Medium: "#FFD600",
  Low: "#00FF41",
  Info: "#00E5FF",
};
