var express = require('express');
var fs = require('fs');
var http = require('http');
var https = require('https');

var key = fs.readFileSync('pem/key.pem');
var cert = fs.readFileSync('pem/cert.pem');
var ca = fs.readFileSync('pem/csr.pem');

var options = {
    key: key,
    cert: cert,
    ca: ca
};

var app = express();
https.createServer(options, app).listen(443);

http.createServer(app).listen(80);

app.use(function(req, res, next) {
    if (req.secure) {
        next();
    } else {
        res.redirect('https://' + req.headers.host + req.url);
    }
});

app.get('/', function(req, res) {
    res.send('Hello, world!');
});
