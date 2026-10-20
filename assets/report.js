// Runs in the exported HTML, without a server or external scripts.
(() => {
  const search = document.getElementById('finding-search');
  const severity = document.getElementById('finding-severity');
  const category = document.getElementById('finding-category');
  const reset = document.getElementById('finding-reset');
  const count = document.getElementById('finding-count');
  if (!search || !severity || !count) return;
  const rows = Array.from(document.querySelectorAll('[data-finding]'));
  const indexed = rows.map(row => ({row, text: row.textContent.toLowerCase()}));
  function filterFindings() {
    const query = search.value.trim().toLowerCase();
    let visible = 0;
    for (const {row, text} of indexed) {
      row.hidden = !((!query || text.includes(query)) &&
        (severity.value === 'all' || row.dataset.severity === severity.value) &&
        (!category || category.value === 'all' || row.dataset.category === category.value));
      if (!row.hidden) visible++;
    }
    count.textContent = `${visible} of ${rows.length} observations shown`;
  }
  search.addEventListener('input', filterFindings);
  severity.addEventListener('change', filterFindings);
  if (category) category.addEventListener('change', filterFindings);
  if (reset) reset.addEventListener('click', () => {
    search.value = ''; severity.value = 'all';
    if (category) category.value = 'all';
    filterFindings(); search.focus();
  });
  filterFindings();
})();
