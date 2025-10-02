function generateUrl(includeCSVOption) {
    const api = "/api/sbomsummaryii";
    args = "";
    if (includeCSVOption) {
        args = "?output=csv"
    }
    args = addSelectedItemsToArgument(args, "namespaceFilter", "namespace");
    args = addSelectedItemsToArgument(args, "packageTypeFilter", "packagetype");
    args = addSortParameter(args, includeCSVOption);
    return api + args;
}

async function loadSBOMTable() {
    console.log("loadSBOMTable()");
    url = generateUrl(false);
    console.log(url)
    const response = await fetch(url);
    console.log("loadSBOMTable() - Got data")
    // Check if the response is OK (status code 200)
    if (!response.ok) {
        throw new Error("Network response was not ok");
    }

    // Parse the JSON data from the response
    const data = await response.json();

    // Get the table body element where rows will be added
    const tableBody = document.querySelector("#sbomTable tbody");

    //Clear the table
    tableBody.replaceChildren();

    data.forEach(item => {
        //console.log(item)
        // Create a new row
        const newRow = document.createElement("tr");
        addCellToRow(newRow, "left", item.name);
        addCellToRow(newRow, "left", item.version);
        addCellToRow(newRow, "left", item.type);
        addCellToRow(newRow, "right", formatNumber(item.image_count));

        // Append the new row to the table body
        tableBody.appendChild(newRow);
    });
}

function onFilterChange() {
    loadSBOMTable();
    document.getElementById("csvlink").href = generateUrl(true);
}

$(function(){
    initFilters();
    loadSBOMTable();
    renderSectionTable("sbom.html", null);
    document.getElementById("csvlink").href = generateUrl(true);
    initClusterName("Image Software Bill of Materials");
});
