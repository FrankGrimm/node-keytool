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

var store = Keytool('example.keystore', 'changeit', {debug: false, storetype: 'JCEKS'});

store.genkeypair('keyalias' + Math.round(Math.random()*100), 'changeit', 'CN=testkey', 120, null, null, null, null, new Date(), function(err, res) {
    if (err) {
        console.log(err);
        return;
    }
    console.log(res.alias, 'created');
    store.genkeypair('testca', 'changeit', 'CN=testca', 356,  function(err, res) {
        console.log(res.alias, 'created');

        store.genkeypair('testca1', 'changeit', 'CN=testca1', 356, function(err, res) {
            console.log(res.alias, 'created');

            store.certreq('testca', 'changeit', 'CN=careq1', 'example.req', function(err, res) {
                console.log('certreq');

                store.certreq('testca', 'changeit', 'CN=stdreq', function(err, res) {
                    var certRequestData = res.outdata;

                    //(alias, keypass, dname, infile, datain, outfile, rfcoutput, validity, sigalg, startdate, cb)
                    store.gencert('testca', 'changeit', 'CN=overridedn', 'example.req', undefined, 'example.crt', true, function(err, res) {
                        console.log('gencert (outfile)');

                        store.gencert('testca', 'changeit', 'CN=testca-req-1', undefined, certRequestData, undefined, function(err, res) {
                            console.log('gencert (std) ' + (res.outdata ? 'got data' : 'no data ' + err));
                            var generatedCertData = res.outdata;

                            store.importcert('imported-fromfile', 'changeit', 'example.crt', function(err, res) {
                                console.log('importcert (file)');

                                store.importcert('imported-fromstdin', 'changeit', undefined, generatedCertData, true, function(err, res) {
                                    console.log('importcert (std)');

                                    // (alias, keypass, data, keyalg, keysize, cb)
                                    store.importpass('imported-pwd-1', undefined, 'banana123', function(err, res) {
                                        console.log('importpass-1');
                                        store.importpass('imported-pwd-2', 'newkeypwd', 'banana1234', function(err, res) {
                                            console.log('importpass-2');

                                            store.changealias('imported-pwd-2', 'newkeypwd', 'imported-aliaschanged', function(err, res) {
                                                console.log('alias changed from ' + res.was + ' to ' + res.alias);

                                                store.deletealias('imported-fromfile', 'changeit', function(err, res) {
                                                    if (!err) console.log('alias imported-fromfile removed from keystore');

                                                    store.storepasswd('changeme', function(err, res) {
                                                        if (!err) console.log('store password changed');

                                                        store.keypasswd('imported-aliaschanged', 'newkeypwd', 'changedkeypwd', function(err, res) {
                                                            console.log('keypass for ' + res.alias + ' changed');

                                                            store.exportcert('imported-fromstdin', 'example.cer', function(err, res) {

                                                                store.exportcert('imported-fromstdin', 'example-rfc.cer', true, function(err, res) {

                                                                    store.getcert('test-rfc.cer', undefined, undefined, undefined, true, function(err, res) {
                                                                        //console.log(res);

                                                                        store.getcert(undefined, require('fs').readFileSync('example-rfc.cer'), undefined, undefined, false, function(err, res) {
                                                                            console.log('Got cert ' + res.Owner);
                                                                            store.list(function(err, res) {
                                                                                printlist(err, res);

                                                                                // the rest of this file is presented by the artist formally known as a callback
                                                                            });
                                                                        });
                                                                    });
                                                                });
                                                            });
                                                        });
                                                    });
                                                });
                                            });
                                        });
                                    });
                                });
                            });
                        });
                    });
                });

            });
        });
    });
});

