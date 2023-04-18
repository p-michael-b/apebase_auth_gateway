require('dotenv').config();
const express = require('express');
const morgan = require('morgan');
const passport = require('passport');
const session = require('express-session');
const knex_session_store = require('connect-session-knex')(session);

const cors = require('cors');
const helmet = require('helmet');
const local_strategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');


const knex = require('knex')({
    client: 'pg',
    searchPath: 'auth',
    connection: {
        database: process.env.DB_NAME,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        host: process.env.DB_HOST,
        port: process.env.DB_PORT,
    },
    pool: {
        min: 2,
        max: 10
    }
});

const PORT = process.env.SERVER_PORT || 5000;
const app = express();
const server = require('http').Server(app);

// For request body parsing
app.use(express.json());

// Cors for different origin communications
// credentials flag allows the client to send the session info in the header
// origin flag allows the server to reflect (enable) the requested origin in the CORS response
app.use(cors({credentials: true, origin: true}))


// Helmet for security
app.use(helmet());

// init Knex session store by passing the Knex's instance to the session store

const store = new knex_session_store({knex: knex,});

const oneDay = 1000 * 60 * 60 * 24;
app.use(session({
    store: store,
    name: 'session',
    secret: process.env.COOKIE_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        maxAge: oneDay
    }
}));

app.use(morgan('\n********** API GATEWAY REQUEST **********\n' +
    'Date       :date[iso]\n' +
    'Request    :method :url\n' +
    'Status     :status\n' +
    'Response   :response-time ms\n' +
    'Remote IP  :remote-addr\n' +
    'HTTP ver.  :http-version\n' +
    'Referrer   :referrer\n' +
    'User Agent :user-agent\n' +
    '********** END REQUEST **********\n\n'));


// Passport for authentication
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser(function (user, done) {
    process.nextTick(function () {
        return done(null, user)
    });
});
passport.deserializeUser(function (user, done) {
    process.nextTick(function () {
        return done(null, user);
    });
});

function isAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    return res.status(403).json({
        status: 403,
        success: false,
        message: 'Unauthenticated. Please log in first',
        data: [],
    });
}

app.get('/', (req, res) => {
    return res.json({
        status: 200,
        success: true,
        message: 'The API gateway',
        data: [],
    });
})


passport.use(new local_strategy({usernameField: 'email', passwordField: 'password'}, async (email, password, done) => {
    knex.select('_id', 'email', 'password')
        .from('auth.users')
        .where({email: email})
        .first()
        .then((database_user) => {
            if (!database_user) {
                console.log('not found', email)
                return done(null, false, 'User not found');
            }
            bcrypt.compare(password, database_user.password, function (err, isMatch) {
                if (err) {
                    console.log('err1', password)
                    return done(err);
                }
                if (!isMatch) {
                    console.log('not same', password)
                    return done(null, false, 'Authentication failed');
                }
                console.log('done', password)
                return done(null, database_user);
            });
        })
        .catch((err) => {
            console.log('err2', err)
            return done(err);
        });
}))

app.post('/login', async (req, res, next) => {
    passport.authenticate('local', async (error, authenticated_user, info) => {
        if (!authenticated_user) {
            return res.json(400, {
                message: info
            })
        }
        req.login(authenticated_user, async (error) => {
            if (error) return next(error)

            const token = jwt.sign({userId: authenticated_user.id}, process.env.JWT_SECRET, {expiresIn: '1h'});
            req.session.token = token;

            return res.status(200).json({
                success: true,
                message: 'Login successful',
                data: {
                    user: authenticated_user
                }
            });
        })
    })(req, res, next);
})

app.post('/mail_service', isAuthenticated, (req, res) => {
    const {mail_recipient, mail_subject, mail_text} = req.body;
    const api_url = 'http://localhost:5001/sendmail';
    fetch(api_url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${req.session.token}` // pass token to mail service
        },
        body: JSON.stringify({mail_recipient, mail_subject, mail_text})
    })
        .then(response => {
            return response.json();
        })
        .then(data => {
            console.log(data.message)
            res.status(200).send(data.message);
        })
        .catch(error => {
            console.error('error', error);
            res.status(500).send('Error sending email');
        });
});

app.post('/database_service', isAuthenticated, (req, res) => {
    const {mail_recipient, mail_subject, mail_text} = req.body;
    // console.log(to, subject, text)
    const api_url = 'http://localhost:5002/finduser';
    fetch(api_url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${req.session.token}` // pass token to mail service
        },
        body: JSON.stringify({mail_recipient, mail_subject, mail_text})
    })
        .then(response => {
            return response.json();
        })
        .then(data => {
            console.log(data.message)
            res.status(200).send(data.message);
        })
        .catch(error => {
            console.error('error', error);
            res.status(500).send('Error sending email');
        });
});


app.post('/rename', isAuthenticated, async (req, res) => {
    const duplicate = await db_controller.findUsername(req.body.user_name)
    if (duplicate.length > 0) {
        return res.status(400).json({
            success: false,
            message: 'This Name is not available'
        })
    } else {
        const user = await db_controller.renameUser(req.body.email, req.body.user_name)
        return res.status(200).json({
            success: true,
            message: 'Your name has been updated',
            user: user
        })
    }
})
app.post('/reset', isAuthenticated, async (req, res) => {
    const token = crypto.randomBytes(20).toString('hex');
    const name = req.user[0].user_name
    const root = (process.env.NODE_ENV === 'development') ? 'http://localhost:3000' : 'https://apebase.app'
    const link = root + '/reset/' + name + '/' + token
    await db_controller.updateTokenUser(req.user[0].email, token)
        .then(async function () {
            emailMessage(req.user[0].email, link, 'reset')
            return res.status(200).json({
                success: true,
                message: 'Password has been changed'
            })
        })
        .catch(function (error) {
            return res.status(400).json({
                success: false,
                message: error
            })
        })
})

app.post('/password', async (req, res, next) => {
    const user = await db_controller.findTokenUser(req.body.user, req.body.token)
    if (user.length === 0) {
        return res.status(400).json({
            success: false,
            message: 'user doesnt exist'
        })
    }
    const valid = new Date(new Date().getTime());
    if (user[0].valid <= valid) {
        return res.status(400).json({
            success: false,
            message: 'Token timed out'
        })
    } else {
        await bcrypt.genSalt(10, function (err, salt) {
            bcrypt.hash(req.body.password, salt, async function (err, hash) {
                const email = await db_controller.updatePassword(user[0].email, hash)
                if (req.body.type === 'set') {
                    const stake = await db_controller.readStake(req.body.stake)
                    await db_controller.rewardInvite(user[0], stake)
                }
                return res.status(200).json({
                    success: true,
                    message: email
                })
            });
        });
    }
})
app.post('/forgot', async (req, res, next) => {
    const user = await db_controller.findUser(req.body.email)
    if (user.length > 0) {
        const token = crypto.randomBytes(20).toString('hex');
        const name = user[0].user_name
        const root = (process.env.NODE_ENV === 'development') ? 'http://localhost:3000' : 'https://apebase.app'
        const link = root + '/reset/' + name + '/' + token
        await db_controller.updateTokenUser(user[0].email, token)
            .then(async function () {
                emailMessage(user[0].email, link, 'forgot')
            })
    }
    return res.status(200).json({
        success: true,
        message: 'Check your email'
    })
})
app.post('/invite', isAuthenticated, async (req, res) => {
        const user = await db_controller.findUser(req.body.friend)
        if (user.length > 0) {
            return res.status(400).json({
                success: false,
                message: 'User exists'
            })
        }
        const asset = await db_controller.readStake(req.body.stake)
        if (parseInt(asset[0].fk_users) === parseInt(req.user[0].id)) {
            const token = crypto.randomBytes(20).toString('hex');
            const name = await db_controller.createUser(req.body.friend, token)
            const root = (process.env.NODE_ENV === 'development') ? 'http://localhost:3000' : 'https://apebase.app'
            const link = root + '/welcome/' + name[0].user_name + '/' + token + '/' + req.body.stake
            emailMessage(req.body.friend, link, 'invite')
            await db_controller.stakeInvite(req.user[0].id, req.body.stake)
            return res.status(200).json({
                success: true,
                message: 'Friend invited'
            })
        } else {
            return res.status(400).json({
                success: false,
                message: 'Doesnt own stake'
            })
        }
    }
)


app.get('/logout', isAuthenticated, (req, res) => {
    // To log out a user there are two options. Enable only one.
    // Option 1: Remove passport object from the session object
    // The session record kept in the database and would be cleared by Knex-session after it expired
    // NOTE: Knex-session clears expired sessions after 60 seconds, adjust 'clearInterval' in the knex-connect options, line 37 to change the clearing interval
    req.logout(() => {
        return res.status(200).json({
            success: true,
            message: 'The user has been logged out'
        })
    })
})

app.get('/reconnect', isAuthenticated, (req, res) => {
    const user = {};
    user.id = req.user[0].id;
    user.email = req.user[0].email;
    user.user_name = req.user[0].user_name;
    user.auth = true;
    return res.status(200).json({
        success: true,
        message: 'The user has been reconnected',
        user: user
    })
})

server.listen(PORT, () => console.log(`server listening on port ${PORT}`));
