var afb = new AFB("api", "mysecret");
var urlws=afb.setURL;
var ws;
var evtidx = 0;
var count = 0;

//**********************************************
// Logger
//**********************************************
var log = {
    commandId: function (id, api, verb, query) {
        console.log("request api=" + api + " verb=" + verb + " query=", query);
        var question = "ws:/" + api + "/" + verb + "?query=" + JSON.stringify(query);
        log._write("question", id + ": " + log.syntaxHighlight(question));
    },

    replyId: function (id, obj) {
        console.log("replyok:" + JSON.stringify(obj));
        log._write("output", id + ": OK: " + log.syntaxHighlight(obj));
    },

    command: function (api, verb, query) {
        log.commandId(0, api, verb, query);
    },

    reply: function (obj) {
        log.replyId(0, obj);
    },

    event: function (obj) {
        console.log("gotevent:" + JSON.stringify(obj));
        log._write("outevt", (evtidx++) + ": " + JSON.stringify(obj));
    },

    error: function (id, obj) {
        console.log("replyerr:" + JSON.stringify(obj));
        log._write("output", id + ": ERROR: " + log.syntaxHighlight(obj));
    },

    _write: function (element, msg) {
        var el = document.getElementById(element);
        el.innerHTML += msg + '\n';

        // auto scroll down
        setTimeout(function () {
            el.scrollTop = el.scrollHeight;
        }, 100);
    },

    syntaxHighlight: function (json) {
        if (typeof json !== 'string') {
            json = JSON.stringify(json, undefined, 2);
        }
        json = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
        return json.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, function (match) {
            var cls = 'number';
            if (/^"/.test(match)) {
                if (/:$/.test(match)) {
                    cls = 'key';
                } else {
                    cls = 'string';
                }
            } else if (/true|false/.test(match)) {
                cls = 'boolean';
            } else if (/null/.test(match)) {
                cls = 'null';
            }
            return '<span class="' + cls + '">' + match + '</span>';
        });
    },
};

//**********************************************
// Generic function to call binder
//***********************************************
function callbinder(api, verb, query) {
    var id = ++count;
    log.commandId(id, api, verb, query);

    // ws.call return a Promise
    return ws.call(api + "/" + verb, query)
        .then(function (res) {
            log.replyId(id, res);
            return res;
        })
        .catch(function (err) {
            log.replyId(id, err);
            throw err;
        });
}

//**********************************************
// Init - establish Websocket connection
//**********************************************
function init(callback) {

    function onopen() {
        document.getElementById("afb_link").innerHTML = "Binder WS Active";
        document.getElementById("afb_link").style.background = "lightgreen";
        if (callback) callback();

        var buttons= document.getElementsByClassName("sgate_button");
        for (var idx=0; idx < buttons.length|0; idx++) {
            buttons[idx].className = "sgate_button sgate_on";
        }
    }

    function onabort() {
        //document.getElementById("afb_api").style.visibility = "hidden";
        document.getElementById("afb_link").innerHTML = "Connected Closed";
        document.getElementById("afb_link").style.background = "red";

        var sgate_box= document.getElementById("sgate_error")
        if (sgate_box) sgate_box.innerHTML= "sgate connection lost"

        var buttons= document.getElementsByClassName("sgate_button");
        for (var idx=0; idx < buttons.length|0; idx++) {
            buttons[idx].className = "sgate_button sgate_off";
        }
    }
    ws = new afb.ws(onopen, onabort);
}
