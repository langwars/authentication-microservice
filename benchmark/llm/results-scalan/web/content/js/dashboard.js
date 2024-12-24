/*
   Licensed to the Apache Software Foundation (ASF) under one or more
   contributor license agreements.  See the NOTICE file distributed with
   this work for additional information regarding copyright ownership.
   The ASF licenses this file to You under the Apache License, Version 2.0
   (the "License"); you may not use this file except in compliance with
   the License.  You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/
var showControllersOnly = false;
var seriesFilter = "";
var filtersOnlySampleSeries = true;

/*
 * Add header in statistics table to group metrics by category
 * format
 *
 */
function summaryTableHeader(header) {
    var newRow = header.insertRow(-1);
    newRow.className = "tablesorter-no-sort";
    var cell = document.createElement('th');
    cell.setAttribute("data-sorter", false);
    cell.colSpan = 1;
    cell.innerHTML = "Requests";
    newRow.appendChild(cell);

    cell = document.createElement('th');
    cell.setAttribute("data-sorter", false);
    cell.colSpan = 3;
    cell.innerHTML = "Executions";
    newRow.appendChild(cell);

    cell = document.createElement('th');
    cell.setAttribute("data-sorter", false);
    cell.colSpan = 7;
    cell.innerHTML = "Response Times (ms)";
    newRow.appendChild(cell);

    cell = document.createElement('th');
    cell.setAttribute("data-sorter", false);
    cell.colSpan = 1;
    cell.innerHTML = "Throughput";
    newRow.appendChild(cell);

    cell = document.createElement('th');
    cell.setAttribute("data-sorter", false);
    cell.colSpan = 2;
    cell.innerHTML = "Network (KB/sec)";
    newRow.appendChild(cell);
}

/*
 * Populates the table identified by id parameter with the specified data and
 * format
 *
 */
function createTable(table, info, formatter, defaultSorts, seriesIndex, headerCreator) {
    var tableRef = table[0];

    // Create header and populate it with data.titles array
    var header = tableRef.createTHead();

    // Call callback is available
    if(headerCreator) {
        headerCreator(header);
    }

    var newRow = header.insertRow(-1);
    for (var index = 0; index < info.titles.length; index++) {
        var cell = document.createElement('th');
        cell.innerHTML = info.titles[index];
        newRow.appendChild(cell);
    }

    var tBody;

    // Create overall body if defined
    if(info.overall){
        tBody = document.createElement('tbody');
        tBody.className = "tablesorter-no-sort";
        tableRef.appendChild(tBody);
        var newRow = tBody.insertRow(-1);
        var data = info.overall.data;
        for(var index=0;index < data.length; index++){
            var cell = newRow.insertCell(-1);
            cell.innerHTML = formatter ? formatter(index, data[index]): data[index];
        }
    }

    // Create regular body
    tBody = document.createElement('tbody');
    tableRef.appendChild(tBody);

    var regexp;
    if(seriesFilter) {
        regexp = new RegExp(seriesFilter, 'i');
    }
    // Populate body with data.items array
    for(var index=0; index < info.items.length; index++){
        var item = info.items[index];
        if((!regexp || filtersOnlySampleSeries && !info.supportsControllersDiscrimination || regexp.test(item.data[seriesIndex]))
                &&
                (!showControllersOnly || !info.supportsControllersDiscrimination || item.isController)){
            if(item.data.length > 0) {
                var newRow = tBody.insertRow(-1);
                for(var col=0; col < item.data.length; col++){
                    var cell = newRow.insertCell(-1);
                    cell.innerHTML = formatter ? formatter(col, item.data[col]) : item.data[col];
                }
            }
        }
    }

    // Add support of columns sort
    table.tablesorter({sortList : defaultSorts});
}

$(document).ready(function() {

    // Customize table sorter default options
    $.extend( $.tablesorter.defaults, {
        theme: 'blue',
        cssInfoBlock: "tablesorter-no-sort",
        widthFixed: true,
        widgets: ['zebra']
    });

    var data = {"OkPercent": 6.543736207872633, "KoPercent": 93.45626379212737};
    var dataset = [
        {
            "label" : "FAIL",
            "data" : data.KoPercent,
            "color" : "#FF6347"
        },
        {
            "label" : "PASS",
            "data" : data.OkPercent,
            "color" : "#9ACD32"
        }];
    $.plot($("#flot-requests-summary"), dataset, {
        series : {
            pie : {
                show : true,
                radius : 1,
                label : {
                    show : true,
                    radius : 3 / 4,
                    formatter : function(label, series) {
                        return '<div style="font-size:8pt;text-align:center;padding:2px;color:white;">'
                            + label
                            + '<br/>'
                            + Math.round10(series.percent, -2)
                            + '%</div>';
                    },
                    background : {
                        opacity : 0.5,
                        color : '#000'
                    }
                }
            }
        },
        legend : {
            show : true
        }
    });

    // Creates APDEX table
    createTable($("#apdexTable"), {"supportsControllersDiscrimination": true, "overall": {"data": [0.06543736207872633, 500, 1500, "Total"], "isController": false}, "titles": ["Apdex", "T (Toleration threshold)", "F (Frustration threshold)", "Label"], "items": [{"data": [0.0, 500, 1500, "Delete"], "isController": false}, {"data": [6.9289985518393025E-6, 500, 1500, "Register"], "isController": false}, {"data": [0.19629971093657936, 500, 1500, "Login"], "isController": false}]}, function(index, item){
        switch(index){
            case 0:
                item = item.toFixed(3);
                break;
            case 1:
            case 2:
                item = formatDuration(item);
                break;
        }
        return item;
    }, [[0, 0]], 3);

    // Create statistics table
    createTable($("#statisticsTable"), {"supportsControllersDiscrimination": true, "overall": {"data": ["Total", 432765, 404446, 93.45626379212737, 17.36306078356583, 0, 717, 24.0, 43.0, 123.0, 140.0, 7202.6662672258835, 14391.37718587207, 405.57119771902666], "isController": false}, "titles": ["Label", "#Samples", "FAIL", "Error %", "Average", "Min", "Max", "Median", "90th pct", "95th pct", "99th pct", "Transactions/s", "Received", "Sent"], "items": [{"data": ["Delete", 144185, 144185, 100.0, 17.35010576689671, 0, 717, 24.0, 43.0, 124.0, 141.0, 2401.082431307244, 4776.098661271857, 96.32370160283098], "isController": false}, {"data": ["Register", 144321, 144320, 99.99930710014482, 17.27394488674576, 0, 428, 24.0, 42.0, 124.0, 137.9900000000016, 2401.987217894947, 4777.752390143382, 180.88930055214365], "isController": false}, {"data": ["Login", 144259, 115941, 80.37002890634207, 17.465163352026256, 0, 509, 24.0, 43.0, 124.0, 137.9900000000016, 2402.1547274119957, 4842.646744882731, 128.47685130257767], "isController": false}]}, function(index, item){
        switch(index){
            // Errors pct
            case 3:
                item = item.toFixed(2) + '%';
                break;
            // Mean
            case 4:
            // Mean
            case 7:
            // Median
            case 8:
            // Percentile 1
            case 9:
            // Percentile 2
            case 10:
            // Percentile 3
            case 11:
            // Throughput
            case 12:
            // Kbytes/s
            case 13:
            // Sent Kbytes/s
                item = item.toFixed(2);
                break;
        }
        return item;
    }, [[0, 0]], 0, summaryTableHeader);

    // Create error table
    createTable($("#errorsTable"), {"supportsControllersDiscrimination": false, "titles": ["Type of error", "Number of errors", "% in errors", "% in all samples"], "items": [{"data": ["400/Bad Request", 28293, 6.9954950722717, 6.537728328307511], "isController": false}, {"data": ["Non HTTP response code: org.apache.http.NoHttpResponseException/Non HTTP response message: localhost:3000 failed to respond", 84832, 20.97486438238974, 19.60232458724712], "isController": false}, {"data": ["Non HTTP response code: java.net.SocketException/Non HTTP response message: Connection reset", 261963, 64.77082231002409, 60.53239055838619], "isController": false}, {"data": ["Non HTTP response code: java.net.SocketException/Non HTTP response message: Connection reset by peer", 952, 0.2353837100626536, 0.2199808209998498], "isController": false}, {"data": ["Non HTTP response code: java.net.SocketException/Non HTTP response message: Broken pipe", 66, 0.0163186185547638, 0.0152507712037711], "isController": false}, {"data": ["401/Unauthorized", 28340, 7.007115906697062, 6.548588725982924], "isController": false}]}, function(index, item){
        switch(index){
            case 2:
            case 3:
                item = item.toFixed(2) + '%';
                break;
        }
        return item;
    }, [[1, 1]]);

        // Create top5 errors by sampler
    createTable($("#top5ErrorsBySamplerTable"), {"supportsControllersDiscrimination": false, "overall": {"data": ["Total", 432765, 404446, "Non HTTP response code: java.net.SocketException/Non HTTP response message: Connection reset", 261963, "Non HTTP response code: org.apache.http.NoHttpResponseException/Non HTTP response message: localhost:3000 failed to respond", 84832, "401/Unauthorized", 28340, "400/Bad Request", 28293, "Non HTTP response code: java.net.SocketException/Non HTTP response message: Connection reset by peer", 952], "isController": false}, "titles": ["Sample", "#Samples", "#Errors", "Error", "#Errors", "Error", "#Errors", "Error", "#Errors", "Error", "#Errors", "Error", "#Errors"], "items": [{"data": ["Delete", 144185, 144185, "Non HTTP response code: java.net.SocketException/Non HTTP response message: Connection reset", 87216, "401/Unauthorized", 28340, "Non HTTP response code: org.apache.http.NoHttpResponseException/Non HTTP response message: localhost:3000 failed to respond", 28272, "Non HTTP response code: java.net.SocketException/Non HTTP response message: Connection reset by peer", 325, "Non HTTP response code: java.net.SocketException/Non HTTP response message: Broken pipe", 32], "isController": false}, {"data": ["Register", 144321, 144320, "Non HTTP response code: java.net.SocketException/Non HTTP response message: Connection reset", 87370, "Non HTTP response code: org.apache.http.NoHttpResponseException/Non HTTP response message: localhost:3000 failed to respond", 28304, "400/Bad Request", 28293, "Non HTTP response code: java.net.SocketException/Non HTTP response message: Connection reset by peer", 337, "Non HTTP response code: java.net.SocketException/Non HTTP response message: Broken pipe", 16], "isController": false}, {"data": ["Login", 144259, 115941, "Non HTTP response code: java.net.SocketException/Non HTTP response message: Connection reset", 87377, "Non HTTP response code: org.apache.http.NoHttpResponseException/Non HTTP response message: localhost:3000 failed to respond", 28256, "Non HTTP response code: java.net.SocketException/Non HTTP response message: Connection reset by peer", 290, "Non HTTP response code: java.net.SocketException/Non HTTP response message: Broken pipe", 18, "", ""], "isController": false}]}, function(index, item){
        return item;
    }, [[0, 0]], 0);

});
