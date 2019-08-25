var crypto = require('crypto');
var express = require('express');
var fs = require('fs');
var http = require('http');
var https = require('https');
var session = require('express-session');
var sqlite3 = require('sqlite3').verbose();

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

if (!fs.existsSync('data/')) {
    fs.mkdirSync('data/');
}

var db = new sqlite3.Database('data/db.sqlite3');

db.serialize(function() {
    db.run('CREATE TABLE IF NOT EXISTS users (' +
        'id INTEGER PRIMARY KEY AUTOINCREMENT, ' +
        'username TEXT NOT NULL, ' +
        'password_hash TEXT NOT NULL, ' +
        'salt TEXT NOT NULL, ' +
        'created REAL NOT NULL, ' +
        'initial_elo REAL NOT NULL, ' +
        'elo REAL NOT NULL, ' +
        'email TEXT)');

    db.run('CREATE TABLE IF NOT EXISTS games (' +
        'id INTEGER PRIMARY KEY AUTOINCREMENT, ' +
        'lower_uid INTEGER NOT NULL, ' +
        'higher_uid INTEGER NOT NULL, ' +
        'begin REAL NOT NULL, ' +
        'end REAL, ' +
        'winner INTEGER, ' +
        'loser INTEGER, ' +
        'data TEXT NOT NULL)');
});

// -----------------------------------------------------------------------------

var is_logged_in = function(req) {
    return req.session && req.session.username;
};

app.get('/', function(req, res) {
    if (is_logged_in(req)) {
        var f = 'src/main.html';
        fs.readFile(f, 'utf8', function(err, data) {
            data = data.replace(/{{my_username}}/g, req.session.username);
            res.send(data);
        });
    } else {
        var f = 'src/index.html';
        fs.readFile(f, 'utf8', function(err, data) {
            res.send(data);
        });
    }
});

app.get('/help', function(req, res) {
    if (is_logged_in(req)) {
        var f = 'src/help_in.html';
    } else {
        var f = 'src/help_out.html';
    }
    fs.readFile(f, 'utf8', function(err, data) {
        res.send(data);
    });
});

app.get('/practice', function(req, res) {
    if (is_logged_in(req)) {
        var f = 'src/practice_in.html';
    } else {
        var f = 'src/practice_out.html';
    }
    fs.readFile(f, 'utf8', function(err, data) {
        res.send(data);
    });
});

app.get('/login', function(req, res) {
    if (is_logged_in(req)) {
        res.redirect('/');
        return;
    }

    fs.readFile('src/login.html', 'utf8', function(err, data) {
        res.send(data);
    });
});

app.get('/register', function(req, res) {
    if (is_logged_in(req)) {
        res.redirect('/');
        return;
    }

    fs.readFile('src/register.html', 'utf8', function(err, data) {
        res.send(data);
    });
});

app.get('/play/:vs', function(req, res) {
    if (!is_logged_in(req)) {
        res.redirect('/');
        return;
    }

    if (!req.params.vs) {
        res.redirect('/');
        return;
    }

    fs.readFile('src/play.html', 'utf8', function(err, data) {
        data = data.replace(/{{vs}}/g, req.params.vs);
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
    return make_error(null);
};

var is_username_valid = function(s) {
    if (!s) {
        return false;
    }

    if (20 < s) {
        return false;
    }

    for (var i = 0; i < s.length; ++i) {
        var c = s[i];
        if ('a' <= c && c <= 'z') {
            continue;
        }
        if ('A' <= c && c <= 'Z') {
            continue;
        }
        if ('0' <= c && c <= '9') {
            continue;
        }
        return false;
    }

    return true;
};

var hash_password = function(password, salt) {
    var x = crypto.createHash('sha256');
    x.update(password);
    x.update(salt);
    return x.digest('hex');
};

app.post('/api/register', function(req, res) {
    if (is_logged_in(req)) {
        res.send(make_error('already_logged_in'));
        return;
    }

    if (!req.body.username) {
        res.send(make_error('username_dne'));
        return;
    }

    if (!is_username_valid(req.body.username)) {
        res.send(make_error('bad_username'));
        return;
    }

    if (!req.body.password) {
        res.send(make_error('password_dne'));
        return;
    }

    if (!req.body.elo) {
        res.send(make_error('elo_dne'));
        return;
    }

    var elo = parseInt(req.body.elo);
    if (!elo) {
        res.send(make_error('bad_elo'));
        return;
    }

    var sql = 'SELECT id FROM users WHERE username=?';
    var params = [req.body.username];
    db.get(sql, params, function(err, row) {
        if (row) {
            res.send(make_error('username_is_taken'));
            return;
        }

        var salt = Math.floor(Math.random() * 0xFFFFFFFF).toString(16);
        var password_hash = hash_password(req.body.password, salt);
        var created = (new Date).getTime() / 1000;

        var sql = 'INSERT INTO users (username, password_hash, salt, ' +
            'created, initial_elo, elo, email) VALUES (?, ?, ?, ?, ?, ?, ' +
            '?)';
        var params = [
            req.body.username,
            password_hash,
            salt,
            created,
            elo,
            elo,
            req.body.email,
        ];
        db.run(sql, params, function(err, ret) {
            req.session.uid = this.lastID;
            req.session.username = req.body.username;
            res.send(make_ok());
        });
    });
});

app.post('/api/login', function(req, res) {
    if (is_logged_in(req)) {
        res.send(make_error('already_logged_in'));
        return;
    }

    if (!req.body.username) {
        res.send(make_error('username_dne'));
        return;
    }

    if (!is_username_valid(req.body.username)) {
        res.send(make_error('bad_username'));
        return;
    }

    if (!req.body.password) {
        res.send(make_error('password_dne'));
        return;
    }

    var sql = 'SELECT id, password_hash, salt FROM users WHERE username=?';
    var params = [req.body.username];
    db.get(sql, params, function(err, row) {
        if (!row) {
            res.send(make_error('user_dne'));
            return;
        }

        var password_hash = hash_password(req.body.password, row.salt);
        if (password_hash != row.password_hash) {
            res.send(make_error('wrong_password'));
            return;
        }

        req.session.uid = row.id;
        req.session.username = req.body.username;
        res.send(make_ok());
    });
});

app.post('/api/logout', function(req, res) {
    if (!is_logged_in(req)) {
        res.send(make_error('not_logged_in'));
        return;
    }

    req.session.destroy();
    res.send(make_ok());
});

app.post('/api/get_users', function(req, res) {
    var sql = 'SELECT username, elo FROM users ORDER BY elo DESC';
    var params = [];
    db.all(sql, params, function(err, rows) {
        var users = [];
        for (var i = 0; i < rows.length; ++i) {
            var row = rows[i];
            var user = {
                username: row.username,
                elo: row.elo
            };
            users.push(user);
        }
        var r = {
            error: null,
            users: users,
        };
        var s = JSON.stringify(r);
        res.send(s);
    });
});

// -----------------------------------------------------------------------------

https.createServer(options, app).listen(443);
http.createServer(app).listen(80);
