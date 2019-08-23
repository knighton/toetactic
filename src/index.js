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

// User database.
var users = [];

// -----------------------------------------------------------------------------

app.get('/', function(req, res) {
    if (req.session.username) {
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
    if (req.session.username) {
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
    if (req.session.username) {
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

// -----------------------------------------------------------------------------

var make_error = function(s) {
    var x = {
        error: s
    };
    return JSON.stringify(x);
};

var make_ok = function() {
    return make_error('');
};

app.post('/api/register', function(req, res) {
    if (req.session.username) {
        res.send(make_error('already_logged_in'));
        return;
    }

    for (var i = 0; i < users.length; ++i) {
        var user = users[i];
        if (req.body.username == user.username) {
            res.send(make_error('username_is_taken'));
            return;
        }
    }

    var user = {
        username: req.body.username,
        password: req.body.password,
    };
    users.push(user);
    req.session.username = user.username;
    res.send(make_ok());
});

app.post('/api/login', function(req, res) {
    if (req.session.username) {
        res.send(make_error('already_logged_in'));
        return;
    }

    for (var i = 0; i < users.length; ++i) {
        var user = users[i];
        if (req.body.username == user.username &&
                req.body.pasword == user.password) {
            req.session.username = user.username;
            res.send(make_ok);
            return;
        }
    }

    res.send(make_error('bad'));
});

app.post('/api/logout', function(req, res) {
    if (!res.session.username) {
        res.send(make_error('not_logged_in'));
        return;
    }

    req.session.destroy();
    res.send(make_ok());
});

// -----------------------------------------------------------------------------

https.createServer(options, app).listen(443);
http.createServer(app).listen(80);
