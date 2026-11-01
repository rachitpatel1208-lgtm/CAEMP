(function () {
  const searchInput = document.getElementById("history-search");
  const riskFilter = document.getElementById("risk-filter");
  const table = document.getElementById("history-table");
  if (!table) return;

  const tbody = table.querySelector("tbody");
  const allRows = Array.from(tbody.querySelectorAll("tr.row-clickable"));

  function applyFilters() {
    const q = (searchInput?.value || "").toLowerCase().trim();
    const level = riskFilter?.value || "";

    let visibleCount = 0;
    allRows.forEach((row) => {
      const target = (row.dataset.target || "").toLowerCase();
      const rowLevel = row.dataset.level || "";
      const matchesSearch = !q || target.includes(q);
      const matchesLevel = !level || rowLevel === level;
      const isVisible = matchesSearch && matchesLevel;
      row.style.display = isVisible ? "" : "none";
      if (isVisible) visibleCount++;
    });

    let noMatchRow = tbody.querySelector(".no-matches-row");
    if (visibleCount === 0 && allRows.length > 0) {
      if (!noMatchRow) {
        noMatchRow = document.createElement("tr");
        noMatchRow.className = "no-matches-row";
        noMatchRow.innerHTML = `<td colspan="6" class="empty-row">// No scan missions match the specified filter criteria.</td>`;
        tbody.appendChild(noMatchRow);
      }
      noMatchRow.style.display = "";
    } else if (noMatchRow) {
      noMatchRow.style.display = "none";
    }
  }

  searchInput?.addEventListener("input", applyFilters);
  riskFilter?.addEventListener("change", applyFilters);

  // Sorting
  const headers = table.querySelectorAll("th.sortable");
  let sortState = { key: null, dir: 1 };

  headers.forEach((th) => {
    th.addEventListener("click", () => {
      const key = th.dataset.key;
      sortState.dir = sortState.key === key ? sortState.dir * -1 : 1;
      sortState.key = key;

      headers.forEach((h) => {
        const arrow = h.querySelector(".sort-arrow");
        if (arrow) arrow.textContent = "";
      });
      const arrow = th.querySelector(".sort-arrow");
      if (arrow) arrow.textContent = sortState.dir === 1 ? "▲" : "▼";

      const colIndex = Array.from(th.parentElement.children).indexOf(th);
      const rows = Array.from(tbody.querySelectorAll("tr.row-clickable"));

      rows.sort((a, b) => {
        const aText = a.children[colIndex]?.textContent.trim() || "";
        const bText = b.children[colIndex]?.textContent.trim() || "";
        const aNum = parseFloat(aText);
        const bNum = parseFloat(bText);
        if (!isNaN(aNum) && !isNaN(bNum)) {
          return (aNum - bNum) * sortState.dir;
        }
        return aText.localeCompare(bText) * sortState.dir;
      });

      rows.forEach((row) => tbody.appendChild(row));
    });
  });
})();
