var express = require('express');
var fs = require('fs');
var http = require('http');
var https = require('https');
var session = require('express-session');

var key = fs.readFileSync('pem/key.pem');
var cert = fs.readFileSync('pem/cert.pem');
var ca = fs.readFileSync('pem/csr.pem');

var options = {
    key: key,
    cert: cert,
    ca: ca
};

var app = express();

app.use(function(req, res, next) {
    if (req.secure) {
        next();
    } else {
        res.redirect('https://' + req.headers.host + req.url);
    }
});

app.use(session({
    secret: 'big-kahuna-burger',
    resave: true,
    saveUninitialized: true
}));

app.use(express.json());
app.use(express.urlencoded());

app.get('/', function(req, res) {
    if (req.session.user) {
        fs.readFile('src/play.html', 'utf8', function(err, data) {
            if (err) {
                res.send('');
                return;
            }
            res.send(data);
        });
    } else {
        fs.readFile('src/index.html', 'utf8', function(err, data) {
            if (err) {
                res.send('');
                return;
            }
            res.send(data);
        });
    }
});

app.get('/login', function(req, res) {
    if (req.session.user) {
        res.redirect('/');
        return;
    }

    fs.readFile('src/login.html', 'utf8', function(err, data) {
        if (err) {
            res.send('');
            return;
        }
        res.send(data);
    });
});

app.get('/register', function(req, res) {
    if (req.session.user) {
        res.redirect('/');
        return;
    }

    fs.readFile('src/register.html', 'utf8', function(err, data) {
        if (err) {
            res.send('');
            return;
        }
        res.send(data);
    });
});

https.createServer(options, app).listen(443);
http.createServer(app).listen(80);
