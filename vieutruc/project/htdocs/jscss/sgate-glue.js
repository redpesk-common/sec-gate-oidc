var idpsdiv;

function addOneIdp (div_box, idp) {

    // create a new dic for this IDP
    var idp_box= document.createElement("div");
    div_box.appendChild(idp_box);
    idp_box.setAttribute("id", idp.uid);
    div_box.className="sgate_idp";

    // add icon
    var logo= document.createElement('img');
    idp_box.appendChild(logo)
    logo.src= idp.logo;
    logo.className= "sgate_logo";

    // add login button
    var button = document.createElement("button");
    idp_box.appendChild(button)
    button.className= "sgate_button";
    button.innerText= idp.uid;
    button.onclick= function() {
        location.href= idp["login-url"];
    }

    // add idp info text
    var info= document.createElement('span');
    info.className= "sgate_info";
    idp_box.appendChild(info)
    info.innerHTML = idp.info;
}

// get IDPs list from sec-gate-oidc
function getConfigIdps() {

    // ws.call return a Promise
    var api="sgate";
    var verb="idp-query-conf";
    var query="{}";
    log.command(api, verb, query);
    ws.call(api + "/" + verb, query)
    .then(function (res) {
        log.reply(res);
        var div_box;
        var sgate_div= document.getElementById("sgate_data");
        sgate_div.className="sgate_box";

        if (sgate_div === null) {
            window.alert("getConfigIdps() require <div id='sgate_data'> in page");
            return;
        }

        // div box is recreated/deleted each time we get/lost binding connection
        sgate_box= document.createElement("div");
        sgate_box.id="sgate_box";
        sgate_div.appendChild(sgate_box);

        // when exit add alias info data
        if (res.response.alias) {
            div_box= document.createElement("div");
            div_box.id="alias_json";
            div_box.className="sgate_extra";
            div_box.innerText= "Request: " + JSON.stringify(res.response.alias);
            sgate_box.appendChild(div_box);
        }

        // add all IDP in a share div
        div_box= document.createElement("div");
        div_box.id="idps_box";
        for (const idp of res.response.idps) {
            addOneIdp(div_box, idp);
        }
        sgate_box.appendChild(div_box);

    })
    .catch(function (err) {
        log.reply(err);
    });
}

// get IDPs list from sec-gate-oidc
function getUserIdps() {

    // ws.call return a Promise
    var api="sgate";
    var verb="idp-query-user";
    var query="{}";
    log.command(api, verb, query);
    ws.call(api + "/" + verb, query)
    .then(function (res) {
        log.reply(res);
        var div_box;
        var sgate_div= document.getElementById("sgate_data");
        sgate_div.className="sgate_box";

        if (sgate_div === null) {
            window.alert("getConfigIdps() require <div id='sgate_data'> in page");
            return;
        }

        // div box is recreated/deleted each time we get/lost binding connection
        sgate_box= document.createElement("div");
        sgate_box.id="sgate_box";
        sgate_div.appendChild(sgate_box);

        // when exit add alias info data
        if (res.response.alias) {
            div_box= document.createElement("div");
            div_box.id="alias_json";
            div_box.className="sgate_extra";
            div_box.innerText= "Request: " + JSON.stringify(res.response.alias);
            sgate_box.appendChild(div_box);
        }

        // add all IDP in a share div
        div_box= document.createElement("div");
        div_box.id="idps_box";
        for (const idp of res.response.idps) {
            addOneIdp(div_box, idp);
        }
        sgate_box.appendChild(div_box);

    })
    .catch(function (err) {
        log.reply(err);
    });
}


// get IDPs list from sec-gate-oidc
function getSession() {

    // ws.call return a Promise
    var api="sgate";
    var verb="session-get";
    var query="{}";
    log.command(api, verb, query);
    ws.call(api + "/" + verb, query)
    .then(function (res) {
        log.reply(res);

        var form= document.getElementById ("sgate_form");
        if (form === null) {
            window.alert("getSession() require <form id='sgate_form'> in page");
           return;
        }

        // loop on every object field and update value when exit
        // res.response[0] => social user definition
        // res.response[1] => idp & loa
        // res.response[2] => used scope
        for (const [key, value] of Object.entries(res.response[0])) {
            var idx;
            var input= document.getElementById (key);
            if (input) {
                input.value= value;
            }
        }
        document.getElementById("pseudo").focus();
    })
    .catch(function (err) {
        var info= document.getElementById ("sgate_error");
        if (info === null) {
            window.alert("getSession() require <form id='sgate_error'> in page");
           return;
        }
        info.innerText=err.response;
        log.reply(err);
    });
}

function sgateCheckAttr(label) {

    this.count;
    if (this.count === undefined) this.count=0;

    // make sure form id march with html page
    var form= document.getElementById ("sgate_form");
    if (form === null) {
        window.alert("registerUser() require <form id='sgate_form'> in page");
        return;
    }

    // retrieve value from HTML form
    var value=form[label].value;
    var query={"label":label};
    query["value"]=value;

    // call user-registration
    var api="sgate";
    var verb="usr-check";
    log.command(api, verb, query);
    ws.call(api + "/" + verb, query)
    .then(function (res) {
        log.reply(res);
        var register= document.getElementById ("sgate_register");
        if (res.response === "locked") {
            // ok for register account
            register.value = "Federate";
            this.count ++;
        } else {
            // ok for register federate
            this.count --;
            if (this.count === 0) register.value = "Register";
        }
    })
    .catch(function (err) {
        var info= document.getElementById ("sgate_error");
        if (info === null) {
            window.alert("checkAttribute() require <form id='sgate_error'> in page");
           return;
        }
        info.innerText=err.response;
        log.reply(err);
    });
}

function sgateReset() {
    var api="sgate";
    var query={};

    verb="session-reset";
    log.command(api, verb, query);
    ws.call(api + "/" + verb, query)
    .then(function (res) {
        log.reply(res);
        // redirect to requested URL
        window.location.replace(res.response.login);
    })
    .catch(function (err) {
        window.location.replace("/")
    });
}

function sgateSubmit() {
    var api="sgate";
    var verb="none";
    var query={};

    // make sure form id march with html page
    var form= document.getElementById ("sgate_form");
    if (form === null) {
        window.alert("registerUser() require <form id='sgate_form'> in page");
        return;
    }

    var register= document.getElementById ("sgate_register");
    if (register === null) {
        window.alert("registerUser() require <button id='sgate_register'> in page");
        return;
    }

    // retrieve value from HTML form
    for (var idx= 0; idx < form.length ;idx++) {
        var uid= form[idx].id;
        var value= form[idx].value;
        if (value) {
            query[uid]=value;
            document.getElementById(uid).style.className = "sgate_input sgate_on";
        } else {
            query[uid]="";
            document.getElementById(uid).style.className = "sgate_input sgate_off";
        }
    }

    if (register.value == "Federate") verb="usr-federate";
    if (register.value === "Register") verb="usr-register";

    log.command(api, verb, query);
    ws.call(api + "/" + verb, query)
    .then(function (res) {
        log.reply(res);
        // redirect to requested URL
        window.location.replace(res.response.target);

    })
    .catch(function (err) {
        var info= document.getElementById ("sgate_error");
        if (info === null) {
            window.alert("sgateSubmit() require <form id='sgate_error'> in page");
        return;
        }
        info.innerText=err.response;
        log.reply(err);
    });
}

function passwordUser(verb) {
    // make sure form id march with html page
    var form= document.getElementById ("sgate_form");
    if (form === null) {
        window.alert("passwordUser() require <form id='sgate_form'> in page");
        return;
    }

    // retrieve value from HTML form
    var query={};
    for (var idx= 0; idx < form.length ;idx++) {
        var uid= form[idx].id;
        var value= form[idx].value;
        if (value) {
            query[uid]=value;
        }
    }

    // call user-registration
    var api="sgate";
    log.command(api, verb, query);
    ws.call(api + "/" + verb, query)
    .then(function (res) {
        log.reply(res);
        // redirect to requested URL
        window.location.replace(res.response.target);

    })
    .catch(function (err) {
        var info= document.getElementById ("sgate_error");
        if (info === null) {
            window.alert("passwordUser() require <form id='sgate_error'> in page");
           return;
        }
        info.innerText=err.response;
        log.reply(err);
    });

}

// wait for smart-card/nfc/mifare token authentication
function pcscReadCard(verb) {
    // call user-registration
    var api="sgate";
    var verb="nfc-scard"
    var query= {"state": urlQuery["state"]};
    log.command(api, verb, query);
    ws.call(api + "/" + verb, query)
    .then(function (res) {
        log.reply(res);
        // redirect to requested URL
        window.location.replace(res.response.target);

    })
    .catch(function (err) {
        var info= document.getElementById ("sgate_error");
        if (info === null) {
            window.alert("passwordUser() require <form id='sgate_error'> in page");
           return;
        }
        info.innerText=err.response;
        log.reply(err);
        // wait 3 second and try again
        setTimeout(function(){ pcscReadCard(); }, 3000);
    });
}

// try to reload page when session terminate if page is protected this will force login
function sessionEventCB(event, name) {
    log.reply(event);
    if (event.data.status === "loa-reset") location.reload(); 
}

function monitorEvents() {

    // register event handler
    ws.onevent ("sgate/session", sessionEventCB);

    // call user-registration
    var api="sgate";
    var verb="session-event"
    var query= {};
    log.command(api, verb, query);
    ws.call(api + "/" + verb, query)
    .then(function (res) {
        log.reply(res);
    })
    .catch(function (err) {
        log.reply(err);
    });
}