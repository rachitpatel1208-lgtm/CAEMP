(function () {
  const searchInput = document.getElementById("history-search");
  const riskFilter = document.getElementById("risk-filter");
  const table = document.getElementById("history-table");
  if (!table) return;

  const tbody = table.querySelector("tbody");
  const allRows = Array.from(tbody.querySelectorAll("tr.row-clickable"));

  function applyFilters() {
    const q = (searchInput?.value || "").toLowerCase();
    const level = riskFilter?.value || "";

    allRows.forEach((row) => {
      const matchesSearch = !q || row.dataset.target.includes(q);
      const matchesLevel = !level || row.dataset.level === level;
      row.style.display = matchesSearch && matchesLevel ? "" : "none";
    });
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
