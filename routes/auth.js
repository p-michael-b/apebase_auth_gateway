const express = require('express');
const passport = require('passport');
const jwt = require('jsonwebtoken');
const {Strategy: local_strategy} = require("passport-local");
const bcrypt = require("bcrypt");

const router = express.Router();

//Local strategy for credential-based authentication.
passport.use(new local_strategy({usernameField: 'email', passwordField: 'password'}, async (email, password, done) => {
    knex.select('_id', 'email', 'password')
        .from('auth.users')
        .where({email: email})
        .first()
        .then((database_user) => {
            if (!database_user) {
                return done(null, false, 'User not found');
            }
            bcrypt.compare(password, database_user.password, function (err, isMatch) {
                if (err) {
                    return done(err);
                }
                if (!isMatch) {
                    return done(null, false, 'Authentication failed');
                }
                return done(null, database_user);
            });
        })
        .catch((err) => {
            return done(err);
        });
}))

//Auth routes

//Login endpoint for acquiring authentication. Sets JWT token to authenticate with microservices
router.post('/login', async (req, res, next) => {
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

module.exports = router;
