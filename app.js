require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const passport = require('passport');
const session = require('express-session');
const knex_session_store = require('connect-session-knex')(session);
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const morgan = require('morgan');

const PORT = process.env.SERVER_PORT || 5001;
const app = express();
const server = require('http').Server(app);
const oneDay = 1000 * 60 * 60 * 24;


// For minimal request body parsing
app.use(express.json());

// Cors for different origin communication, insecure for development
app.use(cors({credentials: true, origin: true}))

// Helmet for security
app.use(helmet());

// Knex for session storage and user database access
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
const store = new knex_session_store({knex: knex,});

//Session for keeping the authentication state and token
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

// Passport for authentication
const localStrategy = require('./localStrategy.js');

passport.use(localStrategy);
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

// Attach knex to the app object to make it available for other routes
app.use((req, res, next) => {
    req.knex = knex;
    next();
});

//after passport can use routes
const authRoutes = require('./routes/auth');
const gatewayRoutes = require('./routes/gateway');

app.use('/auth', authRoutes);
app.use('/gate', gatewayRoutes);

// Morgan for logging
app.use(morgan('\n********** AUTH SERVICE REQUEST **********\n' +
    'Date       :date[iso]\n' +
    'Request    :method :url\n' +
    'Status     :status\n' +
    'Response   :response-time ms\n' +
    'Remote IP  :remote-addr\n' +
    'HTTP ver.  :http-version\n' +
    'Referrer   :referrer\n' +
    'User Agent :user-agent\n' +
    '********** END REQUEST **********\n\n'));


app.get('/', (req, res) => {
    return res.json({
        status: 200,
        success: true,
        message: 'The API auth gateway',
        data: [],
    });
})



// app.post('/database_service', isAuthenticated, (req, res) => {
//     const {mail_recipient, mail_subject, mail_text} = req.body;
//     const api_url = 'http://localhost:5002/finduser';
//     fetch(api_url, {
//         method: 'POST',
//         headers: {
//             'Content-Type': 'application/json',
//             'Authorization': `Bearer ${req.session.token}` // pass token to mail service
//         },
//         body: JSON.stringify({mail_recipient, mail_subject, mail_text})
//     })
//         .then(response => {
//             return response.json();
//         })
//         .then(data => {
//             console.log(data.message)
//             res.status(200).send(data.message);
//         })
//         .catch(error => {
//             console.error('error', error);
//             res.status(500).send('Error sending email');
//         });
// });



//
// app.get('/reconnect', isAuthenticated, (req, res) => {
//     const user = {};
//     user.id = req.user[0].id;
//     user.email = req.user[0].email;
//     user.user_name = req.user[0].user_name;
//     user.auth = true;
//     return res.status(200).json({
//         success: true,
//         message: 'The user has been reconnected',
//         user: user
//     })
// })

server.listen(PORT, () => console.log(`server listening on port ${PORT}`));
