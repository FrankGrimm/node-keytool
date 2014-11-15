node-keytool
============

basic wrapper for the java keytool

## usage

First, require the library:
```javascript
var Keytool = require('node-keytool');
```
Then, open / create your keystore file:
```javascript
// Keytool(filename, storepass, options)
var store = Keytool('example.keystore', 'changeit', {debug: false, storetype: 'JCEKS'});
```
### Options

debug (boolean, if true all keytool output is piped to stdout/stderr)

storetype: keystore type (defaults to JKS, some actions require other storage types), executable (see below)

The library assumes that the keytool executable is on your PATH.
In other cases, you can specify a path to the executable by passing the appropriate option:
```javascript
var store = Keytool(filename, storepass, {executable: '/usr/bin/keytool'});
```
## actions
Most keytool actions are supported with their stdin input method or file-based operations.
All operations expect a callback of the form function(err, result) as the last argument.
See the manpage for keytool for more details.

### Certificate Request: certreq(alias, keypass, dname, outfile, sigalg, cb)

Generated a certificate request for the given alias. If `outfile` is omitted or null, `res.outdata` will contain the certificate data.

### Rename an alias: changealias(alias, keypass, destalias, cb)

Rename `alias` to `destalias`.

### Export a certificate: exportcert(alias, filename, rfcoutput, cb)

Export the given certificate to the output file `filename`.

If `rfcoutput` is true the result is output in RFC 1421 compliant base64 encoding. (Binary DER is the default)

### Generate a keypair: genkeypair(alias, keypass, dname, validity, keysize, keyalg, sigalg, destalias, startdate, x509ext, cb)

Generates a keypair.

`dname`: Distinguished name, e.g. "CN=abc,OU=dev"

`validity`: Integer, Number of days this certificate should be valid

`x509ext`: String-Array, multiple extensions can be specified

`startdate`: JavaScript Date object

### Generate a certificate: gencert(alias, keypass, dname, infile, datain, outfile, rfcoutput, validity, sigalg, startdate, cb)

Generates a certificate from the request given as a) an input file (parameter `infile`) or b) as a string in-memory (parameter `datain`).

If the parameter `outfile` is omitted or null, the result object contains the certificate data.

If the parameter `dname` is specified, this will be used in favor of the distinguished name used to generate the request.

`startdate`: JavasScript Date object

### Import a certificate: importcert(alias, keypass, infile, datain, trustcacerts, cb) 

Import a certificate from a file (parameter `infile`) or from a string (parameter `datain`).

`trustcacerts`: Boolean

### Import a passphrase: importpass(alias, keypass, data, keyalg, keysize, cb)

Import a passphrase into the keystore.

Note: This operation is not supported by the default keystore type (JKS). Use JCEKS or similar if you need this.

### Change a keys password: keypasswd(alias, keypass, newkeypass, cb) 

Change the password for the given `alias` from `keypass` to `newkeypass`

### Change the keystore password: storepasswd(newstorepass, cb)

Change the password for the keystore itself.

### Get basic information on a certificate in the keystore: getcert(file, data, sslserver, jarfile, rfcoutput, cb)

If `rfcoutput` is true, the callback will contain the BASE64 encoded representation of the certificate given in `file` (string, filename) or `data` (string).

If rfcoutput is false, basic certificate information will be parsed from the keytool output (signature algorithms, validity information, issuer / owner - where applicable). 

### Delete an alias from the keystore: deletealias(alias, keypass, cb)

Removes an alias completely

### List the content of the keystore: getlist(cb)

Read the content of the keystore. See examples/listcontent.js for an example on how to use the results.

### Create empty keystore: create(cb)

Creates an empty keystore at the previously specified location. Fails if the targeted file already exists.

