const express = require('express');
const router = express.Router();

// Admin login page
router.get('/login', (req, res) => {
    if (req.session.adminLoggedIn) {
        return res.redirect('/admin/dashboard');
    }
    
    res.render('admin', {
        title: 'Admin Login - Bangalore Connect',
        error: null,
        captcha: generateCaptcha()
    });
});

// Admin login POST
router.post('/login', (req, res) => {
    const { username, password, captcha } = req.body;
    const storedCaptcha = req.body.captchaHidden;
    
    if (captcha !== storedCaptcha) {
        return res.render('admin', {
            title: 'Admin Login - Bangalore Connect',
            error: 'Invalid CAPTCHA',
            captcha: generateCaptcha()
        });
    }
    
    if (username === process.env.ADMIN_USERNAME && password === process.env.ADMIN_PASSWORD) {
        req.session.adminLoggedIn = true;
        req.session.adminUsername = username;
        res.redirect('/admin/dashboard');
    } else {
        res.render('admin', {
            title: 'Admin Login - Bangalore Connect',
            error: 'Invalid username or password',
            captcha: generateCaptcha()
        });
    }
});

// Admin dashboard
router.get('/dashboard', (req, res) => {
    if (!req.session.adminLoggedIn) {
        return res.redirect('/admin/login');
    }
    
    res.render('dashboard', {
        title: 'Admin Dashboard',
        username: req.session.adminUsername
    });
});

// Admin logout
router.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/admin/login');
});

// Generate simple CAPTCHA
function generateCaptcha() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let captcha = '';
    for (let i = 0; i < 6; i++) {
        captcha += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return captcha;
}

module.exports = router;