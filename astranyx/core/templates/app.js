function toggleDetails(id) {
  const row = document.getElementById("details-" + id);
  row.style.display = row.style.display === "table-row" ? "none" : "table-row";
}

function filterRows() {
  const q = document.getElementById("searchBox").value.toLowerCase();
  const checked = Array.from(document.querySelectorAll(".bandFilter:checked")).map(x => x.value);

  document.querySelectorAll(".finding-row").forEach(row => {
    const band = row.dataset.band;
    const text = row.innerText.toLowerCase();
    const visible = checked.includes(band) && text.includes(q);
    row.style.display = visible ? "table-row" : "none";

    const details = row.nextElementSibling;
    if (!visible && details && details.classList.contains("details")) {
      details.style.display = "none";
    }
  });
}

new Chart(document.getElementById("confidenceChart"), {
  type: "doughnut",
  data: {
    labels: ["High", "Medium", "Low"],
    datasets: [{
      data: [HIGH, MEDIUM, LOW]
    }]
  }
});

new Chart(document.getElementById("categoryChart"), {
  type: "bar",
  data: {
    labels: CATEGORY_LABELS,
    datasets: [{
      label: "Findings",
      data: CATEGORY_VALUES
    }]
  },
  options: {
    indexAxis: "y"
  }
});
