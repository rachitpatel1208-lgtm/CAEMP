(function () {
  const form = document.getElementById("scan-form");
  const input = document.getElementById("target-input");
  const btn = document.getElementById("scan-btn");
  const errorEl = document.getElementById("scan-error");
  const overlay = document.getElementById("scan-overlay");
  const stepList = document.getElementById("step-list");
  const progressFill = document.getElementById("overlay-progress-fill");
  const overlayTarget = document.getElementById("overlay-target-name");

  if (!form) return; // scan form only lives on the dashboard

  const STEPS = [
    "Discovering host",
    "Enumerating ports",
    "Detecting services",
    "Calculating risk score",
    "Analyzing exposure changes",
    "Generating report",
  ];

  function buildSteps() {
    stepList.innerHTML = STEPS.map((label, i) => `
      <div class="step-item" data-step="${i}">
        <span class="step-marker"></span>
        <span>${label}</span>
      </div>
    `).join("");
  }

  function updateSteps(currentStep, done) {
    const items = stepList.querySelectorAll(".step-item");
    items.forEach((item, i) => {
      item.classList.remove("active", "complete");
      if (done || i < currentStep) {
        item.classList.add("complete");
      } else if (i === currentStep) {
        item.classList.add("active");
      }
    });
    const pct = done ? 100 : Math.round(((currentStep + 0.5) / STEPS.length) * 100);
    progressFill.style.width = `${pct}%`;
  }

  function showError(message) {
    errorEl.textContent = message;
    errorEl.hidden = false;
  }

  async function pollStatus(scanId) {
    try {
      const res = await fetch(`/api/scan/${scanId}/status`);
      if (!res.ok) throw new Error("Status check failed");
      const data = await res.json();

      if (data.error) {
        overlay.hidden = true;
        btn.disabled = false;
        showError(`Scan failed: ${data.error}`);
        return;
      }

      updateSteps(data.step, data.done);

      if (data.done) {
        setTimeout(() => {
          window.location.href = `/scan/${scanId}`;
        }, 600);
        return;
      }

      setTimeout(() => pollStatus(scanId), 900);
    } catch (err) {
      overlay.hidden = true;
      btn.disabled = false;
      showError("Lost connection to scan engine. Please try again.");
    }
  }

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    errorEl.hidden = true;
    const target = input.value.trim();
    if (!target) return;

    btn.disabled = true;
    buildSteps();
    updateSteps(0, false);
    overlayTarget.textContent = target;
    overlay.hidden = false;

    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target }),
      });
      const data = await res.json();

      if (!res.ok) {
        overlay.hidden = true;
        btn.disabled = false;
        showError(data.error || "Unable to start scan.");
        return;
      }

      pollStatus(data.scan_id);
    } catch (err) {
      overlay.hidden = true;
      btn.disabled = false;
      showError("Could not reach the scan engine. Check that the backend is running.");
    }
  });
})();
