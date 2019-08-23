var bcrypt = require('bcrypt');
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

if (!fs.existsSync('data/')) {
    fs.mkdirSync('data/');
}

var load_user_db = function(filename) {
    if (!fs.existsSync(filename)) {
        return [];
    }
    var user_db = [];
    var lines = fs.readFileSync(filename).toString().split('\n');
    for (var i = 0; i < lines.length; ++i) {
        var line = lines[i];
        var user = JSON.parse(line);
        user_db.push(user);
    }
    return user_db;
};

var save_user_db = function(user_db, filename) {
    if (fs.existsSync(filename)) {
        fs.unlinkSync(filename);
    }
    var lines = [];
    for (var i = 0; i < user_db.length; ++i) {
        var user = user_db[i];
        var line = JSON.stringify(user);
        lines.push(line);
    }
    fs.writeFileSync(filename, lines.join('\n'));
};

var user_db = load_user_db('data/users.jsonl');

var get_user_by_username = function(username) {
    for (var i = 0; i < user_db.length; ++i) {
        var user = user_db[i];
        if (user.username == username) {
            return user;
        }
    }
    return null;
};

// -----------------------------------------------------------------------------

var is_logged_in = function(req) {
    return req.session && req.session.username;
};

app.get('/', function(req, res) {
    if (is_logged_in(req)) {
        var f = 'src/main.html';
    } else {
        var f = 'src/index.html';
    }
    fs.readFile(f, 'utf8', function(err, data) {
        res.send(data);
    });
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

    var vs = get_user_by_username(request.params.vs);
    if (!vs) {
        res.redirect('/');
        return;
    }

    fs.readFile('src/play.html', 'utf8', function(err, data) {
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

app.post('/api/register', function(req, res) {
    if (is_logged_in(req)) {
        res.send(make_error('already_logged_in'));
        return;
    }

    for (var i = 0; i < user_db.length; ++i) {
        var user = user_db[i];
        if (req.body.username == user.username) {
            res.send(make_error('username_is_taken'));
            return;
        }
    }

    var id = user_db.length;
    var user = {
        id: id,
        username: req.body.username,
        password: bcrypt.hashSync(req.body.password, 10),
    };
    user_db.push(user);
    save_user_db(user_db, 'data/users.jsonl');
    req.session.username = user.username;
    res.send(make_ok());
});

app.post('/api/login', function(req, res) {
    if (is_logged_in(req)) {
        res.send(make_error('already_logged_in'));
        return;
    }

    for (var i = 0; i < user_db.length; ++i) {
        var user = user_db[i];
        if (req.body.username == user.username &&
                bcrypt.compareSync(req.body.password, user.password)) {
            req.session.username = user.username;
            res.send(make_ok());
            return;
        }
    }

    res.send(make_error('bad'));
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
    var rr = [];
    for (var i = 0; i < user_db.length; ++i) {
        var user = user_db[i];
        var r = {
            id: user.id,
            username: user.username,
        };
        rr.push(r);
    }
    var r = {
        error: null,
        users: rr,
    };
    res.send(JSON.stringify(r));
});

// -----------------------------------------------------------------------------

https.createServer(options, app).listen(443);
http.createServer(app).listen(80);
