'use strict';

var Keytool = require('../lib/keytool');

var store = Keytool('generated.keystore', 'changeit', {debug: false, storetype: 'JCEKS'});

var gen_alias = 'keyalias' + Math.round(Math.random()*100);
var keypass = "changeit";
var dname = "CN=" + gen_alias;
var validity = 120;
var valid_from = new Date();

// create a CA keypair
   //.genkeypair(alias, keypass, dname, validity, keysize, keyalg, sigalg, destalias, startdate, x509ext, cb)
store.genkeypair(gen_alias, keypass, dname, validity, null, null, null, null, valid_from, ["san=dns:ca1"], function(err, res) {
    if (err) {
        console.log(err);
        return;
    }
    var ca_alias = res.alias;
    console.log('alias', ca_alias, 'created');

    // make request
    store.certreq(ca_alias, 'changeit', 'CN=careq1,OU=example', 'example.req', function(err, res) {
        if (err) {
            console.log(err);
            return;
        }
        console.log('request stored in file example.req');
        
        // generate cert for this request (output to the response object, not a file in this case)
        store.gencert(ca_alias, 'changeit', 'CN=request_override_dn,OU=example', 'example.req', null, null, true, function(err, res) {
            if (err || !res || !res.outdata) {
                console.log(err);
                return;
            }
            console.log('Certificate content (RFC formatted)');
            console.log(res.outdata);

            // import newly generated certificate into the keystore
            store.importcert('imported-fromstdin', 'changeit', undefined, res.outdata, true, function(err, res) {
                if (err) {
                    console.log(err);
                    return;
                }
                console.log('Certificate imported');

            });
        });
    });
});
