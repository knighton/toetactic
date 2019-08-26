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
        'white INTEGER NOT NULL, ' +
        'black INTEGER NOT NULL, ' +
        'begin REAL NOT NULL, ' +
        'end REAL, ' +
        'winner INTEGER, ' +
        'loser INTEGER, ' +
        'data TEXT NOT NULL)');
});

// -----------------------------------------------------------------------------
// UI.

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
// API.

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
    if (!is_logged_in(req)) {
        res.send(make_error('not_logged_in'));
        return;
    }

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

app.post('/api/get_game', function(req, res) {
    if (!is_logged_in(req)) {
        res.send(make_error('not_logged_in'));
        return;
    }

    if (!req.body.vs) {
        res.send(make_error('vs_dne'));
        return;
    }

    var sql = 'SELECT id FROM users WHERE username=?';
    var params = [req.body.vs];
    db.get(sql, params, function(err, row) {
        if (!row) {
            res.send(make_error('no_such_vs'));
            return;
        }

        var vs_uid = row.id;

        var sql = 'SELECT id, white, data FROM games WHERE ' +
            '((white=? AND black=?) OR (white=? AND black=?)) AND ' +
            'end is NULL';
        var params = [req.session.uid, vs_uid, vs_uid, req.session.uid];
        db.get(sql, params, function(err, row) {
            if (row) {
                var x = JSON.parse(row.data);
                if (row.white == req.session.uid) {
                    var color = 'white';
                } else {
                    var color = 'black';
                }
                var head = {
                    type: 'color',
                    body: {
                        color: color,
                    }
                };
                x.unshift(head);
                var r = {
                    error: null,
                    data: x,
                };
                var s = JSON.stringify(r);
                res.send(s);
                return;
            }

            if (Math.random() < 0.5) {
                var white = req.session.uid;
                var black = vs_uid;
            } else {
                var white = vs_uid;
                var black = req.session.uid;
            }
            var begin = (new Date).getTime() / 1000;
            var data = '[]';

            var sql = 'INSERT INTO games (white, black, begin, data) VALUES' +
                '(?, ?, ?, ?)';
            var params = [
                white,
                black,
                begin,
                data,
            ];
            db.run(sql, params);

            if (white == req.session.uid) {
                var color = 'white';
            } else {
                var color = 'black';
            }
            var head = {
                type: 'color',
                body: {
                    color: color,
                }
            };
            data = [head];
            var r = {
                error: null,
                data: data
            };
            var s = JSON.stringify(r);
            res.send(s);
        });
    });
});

app.post('/api/move', function(req, res) {
    if (!is_logged_in(req)) {
        res.send(make_error('not_logged_in'));
        return;
    }

    if (!req.body.vs) {
        res.send(make_error('vs_dne'));
        return;
    }

    var src_y = parseInt(req.body.src_y);
    if (src_y === undefined) {
        res.send(make_error('src_y_dne'));
        return;
    }
    if ([0, 1, 2, 3, 4].indexOf(src_y) == -1) {
        res.send(make_error('bad_src_y'));
        return;
    }

    var src_x = parseInt(req.body.src_x);
    if (src_x === undefined) {
        res.send(make_error('src_x_dne'));
        return;
    }
    if ([0, 1, 2, 3, 4, 5, 6].indexOf(src_x) == -1) {
        res.send(make_error('bad_src_x'));
        return;
    }

    var dst_y = parseInt(req.body.dst_y);
    if (dst_y === undefined) {
        res.send(make_error('dst_y_dne'));
        return;
    }
    if ([0, 1, 2, 3, 4].indexOf(dst_y) == -1) {
        res.send(make_error('bad_dst_y'));
        return;
    }

    var dst_x = parseInt(req.body.dst_x);
    if (dst_x === undefined) {
        res.send(make_error('dst_x_dne'));
        return;
    }
    if ([0, 1, 2, 3, 4, 5, 6].indexOf(dst_x) == -1) {
        res.send(make_error('bad_dst_x'));
        return;
    }

    var sql = 'SELECT id FROM users WHERE username=?';
    var params = [req.body.vs];
    db.get(sql, params, function(err, row) {
        if (!row) {
            res.send(make_error('no_such_vs'));
            return;
        }

        var vs_uid = row.id;

        var sql = 'SELECT id, white, data FROM games WHERE ' +
            '((white=? AND black=?) OR (white=? AND black=?)) AND ' +
            'end is NULL';
        var params = [req.session.uid, vs_uid, vs_uid, req.session.uid];
        db.get(sql, params, function(err, row) {
            if (!row) {
                res.send(make_error('no_such_game'));
                return;
            }

            var gid = row.id;
            var xx = JSON.parse(row.data);
            var x = {
                type: 'move',
                body: {
                    src_y: src_y,
                    src_x: src_x,
                    dst_y: dst_y,
                    dst_x: dst_x,
                }
            };
            xx.push(x);
            var data = JSON.stringify(xx);

            var sql = 'UPDATE games SET data=? WHERE id=?';
            var params = [data, gid];
            db.run(sql, params);
            res.send(make_ok());
        });
    });
});

app.post('/api/resign', function(req, res) {
    if (!is_logged_in(req)) {
        res.send(make_error('not_logged_in'));
        return;
    }

    if (!req.body.vs) {
        res.send(make_error('vs_dne'));
        return;
    }

    var sql = 'SELECT id FROM users WHERE username=?';
    var params = [req.body.vs];
    db.get(sql, params, function(err, row) {
        if (!row) {
            res.send(make_error('no_such_vs'));
            return;
        }

        var vs_uid = row.id;

        var sql = 'SELECT id, white, data FROM games WHERE ' +
            '((white=? AND black=?) OR (white=? AND black=?)) AND ' +
            'end is NULL';
        var params = [req.session.uid, vs_uid, vs_uid, req.session.uid];
        db.get(sql, params, function(err, row) {
            if (!row) {
                res.send(make_error('no_such_game'));
                return;
            }

            var gid = row.id;
            var xx = JSON.parse(row.data);
            var x = {
                type: 'resign',
                body: {}
            };
            xx.push(x);
            var data = JSON.stringify(xx);

            var sql = 'UPDATE games SET data=? WHERE id=?';
            var params = [data, gid];
            db.run(sql, params);
            res.send(make_ok());
        });
    });
});

// -----------------------------------------------------------------------------

https.createServer(options, app).listen(443);
http.createServer(app).listen(80);
