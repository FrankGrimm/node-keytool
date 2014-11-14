'use strict';

var Keytool = require('../lib/keytool');

var printlist = function printlist(err, res) {
    if (err) {
        console.log('Error listing keystore content', err);
        return;
    }

    console.log('Keystore type: ' + res.storetype + ' Provider: ' + res.provider + ' (' + res.certs.length + ' certificates)');
    for (var certidx = 0; certidx < res.certs.length; certidx++) {
        var resobj = res.certs[certidx];
        console.log('#' + certidx, resobj.certtype, '(' + resobj.issued + ')', resobj.alias, resobj.algorithm, resobj.fingerprint);
    }
};

var store = Keytool('generated.keystore', 'changeit', {debug: false, storetype: 'JCEKS'});

console.log('assumed filename: generated.keystore - run generatekeypair.js first if it does not exist');
store.list(function(err, res) {
    printlist(err, res);
});

