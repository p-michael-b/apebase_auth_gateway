const express = require('express');
const router = express.Router();
const passport = require('passport');

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
//Mail Service
router.post('/mail_service', isAuthenticated, (req, res) => {
    const {mail_recipient, mail_subject, mail_text} = req.body;
    const api_url = 'http://localhost:5002/sendmail';
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

module.exports = router;
