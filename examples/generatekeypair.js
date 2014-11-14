'use strict';

var Keytool = require('../lib/keytool');

var store = Keytool('generated.keystore', 'changeit', {debug: false, storetype: 'JCEKS'});

var alias = 'keyalias' + Math.round(Math.random()*100);
var keypass = "changeit";
var dname = "CN=" + alias;
var validity = 120;
var valid_from = new Date();
store.genkeypair(alias, keypass, dname, validity, null, null, null, null, valid_from, function(err, res) {
    if (err) {
        console.log(err);
        return;
    }
    console.log('alias', res.alias, 'created');
});
