'use strict';

var spawn = require('child_process').spawn,
fs = require('fs');

var LineBuffer = function LineBuffer(debug) {
    var bufferContent = null;
    if (debug === undefined) debug = false;

    var handler = function handler(data) {
        if (!bufferContent) {
            bufferContent = data.toString();
        } else {
            bufferContent = bufferContent + data.toString();
        }
        if (debug) console.log(data.toString());
    };

    return {handler: handler, content: function() { return bufferContent; }};
};

/*
* Initialize keytool on specified keystore file
* Possible options:
 * - binary: String (location of keytool binary, default: 'keytool')
*/
var Keytool = function Keytool(keystore, storepass, options) {
    if (!keystore) keystore = 'default.keystore';
    var opts = options || {debug:false};
    var storetype = opts.storetype || 'JKS'; // PKCS11, PKCS12

    var callKeytool = function callKeytool(args, datainput, cb) {
        var calloptions = {
            cwd: undefined,
            env: opts.env || process.env,
        };
        var executable = opts.executable || 'keytool';

        var storeargs = ['-noprompt', '-keystore', keystore, '-storepass', storepass, '-storetype', storetype];
        args = args.concat(storeargs);
        if ('extraargs' in opts) {
            args = args.concat(opts.extraargs);
        }

        var proc = spawn(executable, args);
        if (opts.debug) console.log('Spawning <', executable, args.join(' '), '>');

        var stdoutBuffer = new LineBuffer(opts.debug);
        var stderrBuffer = new LineBuffer(opts.debug);
        proc.stdout.on('data', function(data) {
            stdoutBuffer.handler(data);
        });
        proc.stderr.on('data', function(data) {
            stderrBuffer.handler(data);
        });
        proc.on('close', function(code) {
            cb(code, stdoutBuffer.content(), stderrBuffer.content());
        });

        if (datainput) {
            proc.stdin.write(datainput);
            proc.stdin.end();
        } else {
            proc.stdin.end();
        }
    };

    var debugcb = function(code, stdout, stderr) {
        if (!opts.debug) return;
        console.log('keytool exit (%s)', code);
        console.log('stdout', stdout);
        console.log('stderr', stderr);
    }

    var pushargument = function(target, argname, argvalue) {
        if (!argvalue) return target; // skip empty

        if (argvalue instanceof Function) return target; // skip callbacks

        if (argvalue instanceof Date) { // format according to manpage
            var formatteddate = argvalue.getFullYear() + '/' + 
                ("0" + (argvalue.getMonth() + 1)).slice(-2) + '/' +
                ("0" + argvalue.getDate()).slice(-2) + ' ' +
                ("0" + argvalue.getHours()).slice(-2) + ':' +
                ("0" + argvalue.getMinutes()).slice(-2) + ':' +
                ("0" + argvalue.getSeconds()).slice(-2);
            target.push(argname);
            target.push(formatteddate);
        } else if (Array.isArray(argvalue)) { // arrays, e.g. for multiple -ext values
            for (var idx = 0; idx < argvalue.length; idx++) {
                if (!argvalue[idx]) continue;
                target.push(argname);
                target.push(argvalue[idx]);
            }
        } else { // simple push
            target.push(argname);
            target.push(argvalue);
        }
        return target;
    }

    var handleResult = function(code, stdout, stderr, cb) {
        debugcb(code, stdout, stderr);
        if (code != 0) {
            if (stdout) stdout = stdout.trim();
            if (stderr) stderr = stderr.trim();
            cb(new Error('keytool-' + code + ' ' + stdout), null, stdout, stderr);
            return true;
        }
        return false;
    };

    var certreq = function certreq(alias, keypass, dname, outfile, sigalg, cb) {
        if (!keypass) keypass = storepass;
        cb = arguments[arguments.length-1];

        var callargs = ['-certreq', '-keypass', keypass, '-alias', alias, '-dname', dname];
        pushargument(callargs, '-file', outfile);
        pushargument(callargs, '-sigalg', sigalg);

        callKeytool(callargs, null, function(code, stdout, stderr) {
            if (handleResult(code, stdout, stderr, cb)) return;

            cb(null, {outfile: outfile, outdata: stdout});
        });
        return this;
    };


    var genkeypair = function genkeypair(alias, keypass, dname, validity, keysize, keyalg, sigalg, destalias, startdate, x509ext, cb) {
        if (!keypass) keypass = storepass;
        cb = arguments[arguments.length-1];

        var callargs = ['-genkeypair', '-dname', dname, '-keypass', keypass, '-alias', alias];
        pushargument(callargs, '-keysize', keysize);
        pushargument(callargs, '-keyalg', keyalg);
        pushargument(callargs, '-sigalg', sigalg);
        pushargument(callargs, '-destalias', destalias);
        pushargument(callargs, '-startdate', startdate);
        pushargument(callargs, '-ext', x509ext);
        pushargument(callargs, '-validity', validity);

        callKeytool(callargs, null, function(code, stdout, stderr) {
            if (handleResult(code, stdout, stderr, cb)) return;

            cb(null, {alias: alias});
        });
        return this;
    };

    var gencert = function gencert(alias, keypass, dname, infile, datain, outfile, rfcoutput, validity, sigalg, startdate, cb) {
        if (!keypass) keypass = storepass;
        cb = arguments[arguments.length-1];

        if (datain instanceof Function) datain = null;

        var callargs = ['-gencert', '-keypass', keypass, '-alias', alias];
        pushargument(callargs, '-dname', dname);
        pushargument(callargs, '-sigalg', sigalg);
        pushargument(callargs, '-startdate', startdate);
        pushargument(callargs, '-validity', validity);

        pushargument(callargs, '-infile', infile);
        pushargument(callargs, '-outfile', outfile);

        if (rfcoutput) callargs.push('-rfc');

        callKeytool(callargs, datain, function(code, stdout, stderr) {
            if (handleResult(code, stdout, stderr, cb)) return;

            cb(null, {infile: infile, outfile: outfile, outdata: stdout});
        });
        return this;
    };

    var getlist = function getlist(cb) {
        callKeytool(['-list'], null, function(code, stdout, stderr) {
            if (handleResult(code, stdout, stderr, cb)) return;
            var storeContent = {storetype: null, provider: null, certs: []};

            var lines = stdout.split(/\n/g);
            var readingcerts = false;
            var PRE_STORETYPE = 'Keystore type: ';
            var PRE_PROVIDER = 'Keystore provider: ';
            var PRE_FINGERPRINT = 'Certificate fingerprint (';

                var certline = 0;
                var certinfo = {}
                for(var lineidx = 0; lineidx < lines.length; lineidx++) {
                    var line = lines[lineidx].trim();
                    if (!line || line.length === 0) continue;

                    if (!readingcerts) {
                        if (line.indexOf(PRE_STORETYPE) === 0) {
                            storeContent.storetype = line.substring(PRE_STORETYPE.length);
                        }
                        if (line.indexOf(PRE_PROVIDER) === 0) {
                            storeContent.provider = line.substring(PRE_PROVIDER.length);
                        }
                        if (line.indexOf('contains') > -1) readingcerts = true;
                    } else {
                        if (certline == 0) {
                            line = line.split(',');
                            certinfo.alias = line[0].trim();
                            certinfo.issued = line[1].trim() + ', ' + line[2].trim();
                            certinfo.certtype = line[3].trim();
                            if (certinfo.certtype == 'SecretKeyEntry') {
                                certinfo.algorithm = null;
                                certinfo.fingerprint = null;
                                storeContent.certs.push(certinfo);
                                certinfo = {};
                                continue;
                            }
                            certline++;
                        } else if (certline > 0 && line.indexOf(PRE_FINGERPRINT) > -1) {
                            certinfo.algorithm = line.substring(PRE_FINGERPRINT.length, line.indexOf(')', PRE_FINGERPRINT.length + 1))
                            certinfo.fingerprint = line.substring(PRE_FINGERPRINT.length + certinfo.algorithm.length + 3);
                            certline = 0;
                            storeContent.certs.push(certinfo);
                            certinfo = {};
                        }
                    }


                }

                cb(null, storeContent);
        });
        return this;
    };

    var importcert = function importcert(alias, keypass, infile, datain, trustcacerts, cb) { 
        if (!keypass) keypass = storepass;
        cb = arguments[arguments.length-1];

        var callargs = ['-importcert', '-keypass', keypass, '-alias', alias];
        if (trustcacerts === true) callargs.push('-trustcacerts');
        pushargument(callargs, '-file', infile);

        if (datain instanceof Function) datain = null;

        callKeytool(callargs, datain, function(code, stdout, stderr) {
            if (handleResult(code, stdout, stderr, cb)) return;

            cb(null, {infile: infile, datain: (!!datain)});
        });

        return this;
    };

    /* note: importing passwords does not work with the default storetype JKS, requires JCEKS or similar */
    var importpass = function importpass(alias, keypass, data, keyalg, keysize, cb) { 
        if (!keypass) keypass = storepass;
        cb = arguments[arguments.length-1];
        if (!data || data instanceof Function) data = null;

        if (!data) {
            setTimeout(function() { cb(new Error('no-data'), null); }, 0);
            return this;
        }

        var callargs = ['-importpass', '-keypass', keypass, '-alias', alias];
        pushargument(callargs, '-keyalg', keyalg);
        pushargument(callargs, '-keysize', keysize);

        callKeytool(callargs, data, function(code, stdout, stderr) {
            if (handleResult(code, stdout, stderr, cb)) return;

            cb(null, {alias: alias});
        });

        return this;
    };

    var changealias = function changealias(alias, keypass, destalias, cb) { 
        if (!keypass) keypass = storepass;
        cb = arguments[arguments.length-1];

        var callargs = ['-changealias', '-keypass', keypass, '-alias', alias, '-destalias', destalias];

        callKeytool(callargs, undefined, function(code, stdout, stderr) {
            if (handleResult(code, stdout, stderr, cb)) return;

            cb(null, {alias: destalias, was: alias});
        });

        return this;
    };

    var deletealias = function deletealias(alias, keypass, cb) { 
        if (!keypass) keypass = storepass;
        cb = arguments[arguments.length-1];

        var callargs = ['-delete', '-keypass', keypass, '-alias', alias];

        callKeytool(callargs, undefined, function(code, stdout, stderr) {
            if (handleResult(code, stdout, stderr, cb)) return;

            cb(null, {alias: alias});
        });

        return this;
    };

    var keypasswd = function keypasswd(alias, keypass, newkeypass, cb) { 
        if (!keypass) keypass = storepass;
        cb = arguments[arguments.length-1];

        var callargs = ['-keypasswd', '-keypass', keypass, '-alias', alias, '-new', newkeypass];

        callKeytool(callargs, undefined, function(code, stdout, stderr) {
            if (handleResult(code, stdout, stderr, cb)) return;

            cb(null, {alias: alias});
        });

        return this;
    };

    var storepasswd = function storepasswd(newstorepass, cb) {
        cb = arguments[arguments.length-1];

        var callargs = ['-storepasswd', '-new', newstorepass];

        callKeytool(callargs, undefined, function(code, stdout, stderr) {
            if (handleResult(code, stdout, stderr, cb)) return;

            storepass = newstorepass;
            cb(null, {pw_changed: true});
        });

        return this;
    }

    var exportcert = function exportcert(alias, filename, rfcoutput, cb) { 
        cb = arguments[arguments.length-1];

        var callargs = ['-exportcert', '-alias', alias, '-file', filename];
        if (rfcoutput === true) callargs.push('-rfc');

        callKeytool(callargs, undefined, function(code, stdout, stderr) {
            if (handleResult(code, stdout, stderr, cb)) return;

            cb(null, {alias: alias});
        });

        return this;
    };

    var getcert = function getcert(file, data, sslserver, jarfile, rfcoutput, cb) { 
        cb = arguments[arguments.length-1];

        var callargs = ['-printcert'];
        if (rfcoutput === true) callargs.push('-rfc');
        pushargument(callargs, '-file', file);
        pushargument(callargs, '-sslserver', sslserver);
        pushargument(callargs, '-jarfile', jarfile);

        if (!data || data instanceof Function) data = null;

        callKeytool(callargs, data, function(code, stdout, stderr) {
            if (handleResult(code, stdout, stderr, cb)) return;

            if (rfcoutput === true) {
                cb(null, stdout);
            } else {
                var lines = stdout.split('\n');
                var certdata = {};
                var lineHeader = null;
                for(var lineidx = 0; lineidx < lines.length; lineidx++) {
                    var line = lines[lineidx].trim();
                    if (line == '') continue;
                    if (line == 'Extensions:') break;

                    if (line.indexOf('Valid from: ') === 0) {
                        line = line.substring('Valid from: '.length);
                        line = line.split(' until: ');
                        certdata['valid_from'] = line[0];
                        certdata['valid_until'] = line[1];
                    } else if (line.indexOf(':') === (line.length - 1)) {
                        lineHeader = line.substring(0, line.length - 1);
                    } else if (line.indexOf(': ') > -1) {
                        var delimPosition = line.indexOf(': ');
                        if (lineHeader === null) {
                            certdata[line.substring(0, delimPosition)] = line.substring(delimPosition + 2);
                        } else {
                            if (!(lineHeader in certdata)) certdata[lineHeader] = {};
                            certdata[lineHeader][line.substring(0, delimPosition)] = line.substring(delimPosition + 2);
                        }
                    }
                }
                cb(null, certdata, stdout);
            }
        });

        return this;
    };

    /*
    * Convenience method to create an empty keystore. 
    * Fails if the specified file already exists.
    */
    var create = function create(cb) {
        fs.exists(keystore, function(exists) {
            if (exists) {
                cb(new Error('File ' + keystore + ' already exists.'), null);
                return;
            }

            genkeypair('removeafteruse', 'changeit', 'CN=remove', function(err, res) {
                if (err) return cb(err, res);
                deletealias('removeafteruse', 'changeit', function(err, res) {
                    if (err) return cb(err, res);
                    cb(null, {'created': keystore});
                });
            });
        });

        return this;
    }

    return {
        create: create,
        certreq: certreq,
        changealias: changealias,
        exportcert: exportcert,
        genkeypair: genkeypair,
        gencert: gencert,
        importcert: importcert,
        importpass: importpass,
        keypasswd: keypasswd,
        storepasswd: storepasswd,
        getcert: getcert,
        deletealias: deletealias,
        list: getlist,
    };
};

var debugrescb = function(err, res) {
    console.log(err, res);
};


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

module.exports = exports = Keytool;

