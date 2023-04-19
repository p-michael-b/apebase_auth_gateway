const bcrypt = require('bcrypt');

// localStrategy.js
const LocalStrategy = require('passport-local').Strategy;
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

module.exports = new LocalStrategy({usernameField: 'email', passwordField: 'password'}, async (email, password, done) => {
    knex.select('_id', 'email', 'password')
        .from('auth.users')
        .where({email: email})
        .first()
        .then((database_user) => {
            if (!database_user) {
                return done(null, null, 'User not found');
            }
            bcrypt.compare(password, database_user.password, function (error, isMatch) {
                if (error) {
                    return done(error, null, 'Bcrypt error');
                }
                if (!isMatch) {
                    return done(null, null, 'Password does not match');
                }
                return done(null, database_user, 'Successfully authenticated');
            });
        })
        .catch((err) => {
            return done(error, null, 'knex error');
        });
});