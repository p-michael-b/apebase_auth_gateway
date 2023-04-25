const express = require('express');
const passport = require('passport');
const jwt = require('jsonwebtoken');
const {Strategy: local_strategy} = require("passport-local");
const bcrypt = require("bcrypt");
const crypto = require("crypto");

const router = express.Router();

//middleware for protecting the routes
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


//Auth routes

//Login endpoint for acquiring authentication. Sets JWT token to authenticate with microservices
router.post('/login', async (req, res, next) => {
    passport.authenticate('local', async (error, authenticated_user) => {
        if (!authenticated_user) {
            return res.status(400).json({
                success: false,
                message: 'You shall not pass!',
            });
        }
        req.login(authenticated_user, async (error) => {
            if (error) return next(error)

            req.session.token = jwt.sign({userId: authenticated_user.id}, process.env.JWT_SECRET, {expiresIn: '1h'});

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

router.get('/logout', isAuthenticated, (req, res) => {
    req.logout(() => {
        req.session.destroy(() => {
            return res.status(200).json({
                success: true,
                message: 'The user has been logged out'
            })
        })
    })
})

router.post('/rename', isAuthenticated, (req, res) => {
    const knex = req.knex;
    const session_user = req.user;
    const {username} = req.body;
    knex.select('_id')
        .from('auth.users')
        .where({username: username})
        .first()
        .then((database_user) => {
            if (!database_user) {
                knex('auth.users')
                    .where({_id: session_user._id})
                    .update({username: username})
                    .then(() => {
                        return res.status(200).json({
                            success: true,
                            message: 'Username updated successfully'
                        });
                    })
                    .catch((error) => {
                        return res.status(500).json({
                            success: false,
                            message: 'Error updating username'
                        });
                    });
            } else {
                return res.status(409).json({
                    success: false,
                    message: 'This name is taken'
                });
            }
        })
        .catch((error) => {
            return res.status(500).json({
                success: false,
                message: 'Error retrieving user'
            });
        });
})

router.post('/password', isAuthenticated, (req, res) => {
    const knex = req.knex;
    const session_user = req.user;
    const {password} = req.body;
    console.log(session_user)
    bcrypt.genSalt(10)
        .then((salt) => {
            bcrypt.hash(password, salt, async function (error, hash) {
                knex('auth.users')
                    .where({_id: session_user._id})
                    .update({password: hash})
                    .then(() => {
                        return res.status(200).json({
                            success: true,
                            message: 'Password updated successfully'
                        });
                    })
                    .catch((error) => {
                        return res.status(500).json({
                            success: false,
                            message: 'Error updating password',
                            error: error
                        });
                    });
            });
        })
        .catch((error) => {
            return res.status(500).json({
                success: false,
                message: 'Error generating hash',
                error: error
            });
        });
})

router.post('/invite', isAuthenticated, async (req, res) => {
    const knex = req.knex;
    const {mail_recipient} = req.body;
    try {
        const database_user = await knex.select('_id')
            .from('auth.users')
            .where({email: mail_recipient})
            .first()
        if (database_user) {
            throw new Error("This ape is with us already");
        }
        const max_result = await knex.max('_id')
            .from('auth.users');
        const serial = (max_result[0].max + 1).toString().padStart(5, '0');
        const token = crypto.randomBytes(20).toString('hex');
        const root = (process.env.NODE_ENV === 'development') ? 'http://localhost:3000' : 'https://apebase.app'
        const api_url = (process.env.NODE_ENV === 'development') ? 'http://localhost:5002/sendmail' : 'https://apebase.app/sendmail';
        const link = root + '/welcome/ape_' + serial + '/' + token
        const mail_subject = 'Heiliger Bimbam!'
        const mail_text = `You have been invited to join the apebase. Rare Item! Please follow the link:
        
        ${link}}`
        fetch(api_url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${req.session.token}` // pass token to mail service
            },
            body: JSON.stringify({mail_recipient, mail_subject, mail_text})
        })
            .then(() => {
                return res.status(200).json({
                    success: true,
                    message: 'You are a true friend',
                    link: link,
                    error: null
                });
            }
        )
            .catch((error) => {
            return res.status(500).json({
                success: true,
                message: 'Error',
                error: error
            });
        })


    } catch (error) {
        return res.status(500).json({
            success: false,
            message: 'Error inviting user',
            error: error.message
        });
    }


})


//             const token = crypto.randomBytes(20).toString('hex');
//             const name = await db_controller.createUser(req.body.friend, token)
//             const root = (process.env.NODE_ENV === 'development') ? 'http://localhost:3000' : 'https://apebase.app'
//             const link = root + '/welcome/' + name[0].user_name + '/' + token + '/' + req.body.stake
//             emailMessage(req.body.friend, link, 'invite')
//             await db_controller.stakeInvite(req.user[0].id, req.body.stake)
//             return res.status(200).json({
//                 success: true,
//                 message: 'Friend invited'
//             })
//         } else {
//             return res.status(400).json({
//                 success: false,
//                 message: 'Doesnt own stake'
//             })
//         }
//     }
// )


// router.post('/reset', isAuthenticated, async (req, res) => {
//     const token = crypto.randomBytes(20).toString('hex');
//     const name = req.user[0].user_name
//     const root = (process.env.NODE_ENV === 'development') ? 'http://localhost:3000' : 'https://apebase.app'
//     const link = root + '/reset/' + name + '/' + token
//     await db_controller.updateTokenUser(req.user[0].email, token)
//         .then(async function () {
//             emailMessage(req.user[0].email, link, 'reset')
//             return res.status(200).json({
//                 success: true,
//                 message: 'Password has been changed'
//             })
//         })
//         .catch(function (error) {
//             return res.status(400).json({
//                 success: false,
//                 message: error
//             })
//         })
// })


// router.post('/forgot', async (req, res, next) => {
//     const user = await db_controller.findUser(req.body.email)
//     if (user.length > 0) {
//         const token = crypto.randomBytes(20).toString('hex');
//         const name = user[0].user_name
//         const root = (process.env.NODE_ENV === 'development') ? 'http://localhost:3000' : 'https://apebase.app'
//         const link = root + '/reset/' + name + '/' + token
//         await db_controller.updateTokenUser(user[0].email, token)
//             .then(async function () {
//                 emailMessage(user[0].email, link, 'forgot')
//             })
//     }
//     return res.status(200).json({
//         success: true,
//         message: 'Check your email'
//     })
// })


module.exports = router;
