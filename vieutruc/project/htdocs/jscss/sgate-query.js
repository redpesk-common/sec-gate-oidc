// retrieve queryy params
var urlQuery;
(window.onpopstate = function () {
var match,
    pl     = /\+/g,  // Regex for replacing addition symbol with a space
    search = /([^&=]+)=?([^&]*)/g,
    decode = function (s) { return decodeURIComponent(s.replace(pl, " ")); },
    query  = window.location.search.substring(1);

urlQuery = {};
while (match = search.exec(query))
    urlQuery[decode(match[1])] = decode(match[2]);
})();

// Usage:
// <head>
// 	  <title>xxxxx</title>
//    <meta charset="utf-8">
// 	  <link rel="stylesheet" href="/jscss/sgate-binding.css">
// 	  <link rel="icon" type="image/x-icon" href="/assets/favicon.ico">
// 	  <script src="/jscss/parse-query.js"></script>
// </head>
//
// <body class="page-content">
//    <h2 id="error_info"></h2>
// 	  <img src="/assets/iot-bzh-korigan.png">
// </body>
//
// <script>
//    // place here your DIV-ID replacement
//    document.getElementById("error_info").innerHTML= urlQuery["info"];
// </script>