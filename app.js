const express = require('express');
const fs = require('fs').promises;
const path = require('path');
const session = require('express-session');
require('dotenv').config();

const app = express();

// ============ CRITICAL FOR RENDER ============
// Trust Render's proxy for secure cookies
app.set('trust proxy', 1);

// ============ MIDDLEWARE ============
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Session configuration optimized for Render
app.use(session({
    secret: process.env.SESSION_SECRET || 'bangalore-connect-secret-key-123456789',
    resave: false,
    saveUninitialized: false,
    proxy: true, // Trust Render's reverse proxy
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        sameSite: 'lax'
    }
}));

// Debug middleware (can remove after testing)
app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
    next();
});

// Set EJS as templating engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// ============ HELPER FUNCTIONS ============
const jobsFilePath = path.join(__dirname, 'data', 'jobs.json');

async function readJobs() {
    try {
        const data = await fs.readFile(jobsFilePath, 'utf8');
        return JSON.parse(data);
    } catch (err) {
        console.error('Error reading jobs file:', err);
        return [];
    }
}

async function writeJobs(jobs) {
    try {
        await fs.writeFile(jobsFilePath, JSON.stringify(jobs, null, 2), 'utf8');
        return true;
    } catch (err) {
        console.error('Error writing jobs file:', err);
        return false;
    }
}

function formatDate(dateString) {
    const date = new Date(dateString);
    const now = new Date();
    const diffTime = Math.abs(now - date);
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    
    if (diffDays === 1) return 'Today';
    if (diffDays <= 7) return `${diffDays} days ago`;
    return date.toLocaleDateString('en-IN', { 
        day: 'numeric', 
        month: 'short', 
        year: 'numeric' 
    });
}

function generateCaptcha() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let captcha = '';
    for (let i = 0; i < 6; i++) {
        captcha += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return captcha;
}

// ============ MIDDLEWARES ============
const isAdmin = (req, res, next) => {
    console.log('Admin check:', req.session.adminLoggedIn);
    if (req.session.adminLoggedIn) {
        next();
    } else {
        res.redirect('/admin/login');
    }
};

// ============ ROUTES ============

// ----- PUBLIC ROUTES -----

// Homepage
app.get('/', async (req, res) => {
    try {
        const jobs = await readJobs();
        const activeJobs = jobs.filter(job => job.status === 'active');
        
        // Pagination
        const page = parseInt(req.query.page) || 1;
        const limit = 10;
        const startIndex = (page - 1) * limit;
        const endIndex = startIndex + limit;
        const paginatedJobs = activeJobs.slice(startIndex, endIndex);
        const totalPages = Math.ceil(activeJobs.length / limit);
        
        res.render('index', {
            title: 'Bangalore Connect - Find Your Dream Job',
            jobs: paginatedJobs,
            currentPage: page,
            totalPages,
            hasNextPage: endIndex < activeJobs.length,
            hasPrevPage: startIndex > 0,
            query: '',
            filters: {},
            formatDate: formatDate
        });
    } catch (err) {
        console.error('Error loading homepage:', err);
        res.status(500).render('error', { 
            title: 'Server Error',
            error: 'Error loading homepage' 
        });
    }
});

// Job Detail Page
app.get('/job/:id', async (req, res) => {
    try {
        const jobs = await readJobs();
        const job = jobs.find(j => j.id === parseInt(req.params.id) && j.status === 'active');
        
        if (!job) {
            return res.status(404).render('error', { 
                title: 'Job Not Found',
                error: 'Job not found or has been removed' 
            });
        }
        
        res.render('job-detail', {
            title: `${job.title} at ${job.company}`,
            job,
            formatDate: formatDate
        });
    } catch (err) {
        console.error('Error loading job detail:', err);
        res.status(500).render('error', { 
            title: 'Server Error',
            error: 'Error loading job details' 
        });
    }
});

// WhatsApp redirect
app.get('/whatsapp', (req, res) => {
    res.redirect('https://chat.whatsapp.com/KhTXl9CNMbSG8mv6nYCAAW');
});

// ----- ADMIN ROUTES -----

// Admin Login Page
app.get('/admin/login', (req, res) => {
    if (req.session.adminLoggedIn) {
        console.log('Already logged in, redirecting to dashboard');
        return res.redirect('/admin/dashboard');
    }
    
    res.render('admin', {
        title: 'Admin Login',
        error: null,
        captcha: generateCaptcha()
    });
});

// Admin Login POST
app.post('/admin/login', (req, res) => {
    console.log('Login attempt:', req.body.username);
    
    const { username, password, captcha } = req.body;
    const storedCaptcha = req.body.captchaHidden;
    
    // CAPTCHA validation
    if (captcha !== storedCaptcha) {
        console.log('CAPTCHA failed');
        return res.render('admin', {
            title: 'Admin Login',
            error: 'Invalid CAPTCHA. Please try again.',
            captcha: generateCaptcha()
        });
    }
    
    // Admin credentials - CHANGE THESE IN PRODUCTION!
    const adminUsername = process.env.ADMIN_USERNAME || 'Ruhan@0312';
    const adminPassword = process.env.ADMIN_PASSWORD || 'Ruhan@0312';
    
    if (username === adminUsername && password === adminPassword) {
        console.log('Login successful for:', username);
        req.session.adminLoggedIn = true;
        req.session.adminUsername = username;
        req.session.save((err) => {
            if (err) {
                console.error('Session save error:', err);
                return res.render('admin', {
                    title: 'Admin Login',
                    error: 'Login failed. Please try again.',
                    captcha: generateCaptcha()
                });
            }
            console.log('Session saved, redirecting to dashboard');
            res.redirect('/admin/dashboard');
        });
    } else {
        console.log('Invalid credentials');
        res.render('admin', {
            title: 'Admin Login',
            error: 'Invalid username or password',
            captcha: generateCaptcha()
        });
    }
});

// Admin Dashboard
app.get('/admin/dashboard', isAdmin, async (req, res) => {
    try {
        const jobs = await readJobs();
        const activeJobs = jobs.filter(job => job.status === 'active');
        
        // Get success/error messages from query parameters
        const success = req.query.success;
        const error = req.query.error;
        
        res.render('dashboard', {
            title: 'Admin Dashboard',
            username: req.session.adminUsername,
            totalJobs: activeJobs.length,
            recentJobs: activeJobs.slice(0, 5),
            success: success,
            error: error
        });
    } catch (err) {
        console.error('Error loading dashboard:', err);
        res.status(500).render('error', { 
            title: 'Server Error',
            error: 'Error loading dashboard' 
        });
    }
});

// Post Job Page (Form) - GET
app.get('/admin/post-job', isAdmin, (req, res) => {
    res.render('post-job', {
        title: 'Post New Job',
        username: req.session.adminUsername,
        job: null,
        error: null,
        success: null
    });
});

// Submit New Job - POST
app.post('/admin/post-job', isAdmin, async (req, res) => {
    try {
        const {
            title,
            company,
            location,
            type,
            experience,
            salary,
            applyLink,
            shortDescription,
            fullDescription
        } = req.body;
        
        console.log('Job form submitted:', { title, company, location });
        
        // Validation
        if (!title || !company || !location || !shortDescription || !fullDescription) {
            return res.render('post-job', {
                title: 'Post New Job',
                username: req.session.adminUsername,
                job: req.body,
                error: 'Please fill all required fields (Title, Company, Location, and both descriptions)',
                success: null
            });
        }
        
        // Read existing jobs
        const jobs = await readJobs();
        
        // Create new job ID
        let newId = 1;
        if (jobs.length > 0) {
            const maxId = Math.max(...jobs.map(j => j.id));
            newId = maxId + 1;
        }
        
        // Create new job
        const newJob = {
            id: newId,
            title: title.trim(),
            company: company.trim(),
            location: location.trim(),
            type: type || 'Full-time',
            experience: experience || 'Fresher',
            postedDate: new Date().toISOString(),
            salary: salary || 'Not disclosed',
            applyLink: applyLink || '',
            shortDescription: shortDescription.trim(),
            fullDescription: fullDescription.trim(),
            status: 'active'
        };
        
        console.log('New job created:', newJob);
        
        // Add to jobs array
        jobs.push(newJob);
        
        // Save to file
        const saved = await writeJobs(jobs);
        
        if (!saved) {
            throw new Error('Failed to save job to database');
        }
        
        console.log('Job saved successfully to jobs.json');
        
        // Show success message on post-job page
        res.render('post-job', {
            title: 'Post New Job',
            username: req.session.adminUsername,
            job: null,
            error: null,
            success: 'Job posted successfully! You can post another job or go back to dashboard.'
        });
        
    } catch (err) {
        console.error('Error posting job:', err);
        res.render('post-job', {
            title: 'Post New Job',
            username: req.session.adminUsername,
            job: req.body,
            error: `Error posting job: ${err.message}`,
            success: null
        });
    }
});

// Delete Job
app.post('/admin/delete-job/:id', isAdmin, async (req, res) => {
    try {
        const jobs = await readJobs();
        const updatedJobs = jobs.map(job => 
            job.id === parseInt(req.params.id) 
                ? { ...job, status: 'deleted' } 
                : job
        );
        
        await writeJobs(updatedJobs);
        res.redirect('/admin/dashboard?success=Job deleted successfully!');
    } catch (err) {
        console.error('Error deleting job:', err);
        res.redirect('/admin/dashboard?error=Error deleting job');
    }
});

// Admin Logout
app.get('/admin/logout', (req, res) => {
    console.log('Logging out admin:', req.session.adminUsername);
    req.session.destroy((err) => {
        if (err) {
            console.error('Error destroying session:', err);
        }
        res.redirect('/admin/login');
    });
});

// ============ SERVER INITIALIZATION ============
const PORT = process.env.PORT || 3000;
const HOST = '0.0.0.0';

async function initializeDataDirectory() {
    try {
        const dataDir = path.join(__dirname, 'data');
        await fs.mkdir(dataDir, { recursive: true });
        
        const jobsFile = path.join(dataDir, 'jobs.json');
        try {
            await fs.access(jobsFile);
            console.log('✅ jobs.json exists');
        } catch {
            await fs.writeFile(jobsFile, '[]', 'utf8');
            console.log('✅ Created jobs.json file');
        }
        
        console.log('✅ Data directory initialized');
    } catch (err) {
        console.error('Error initializing data directory:', err);
    }
}

app.listen(PORT, HOST, async () => {
    await initializeDataDirectory();
    
    console.log('='.repeat(50));
    console.log(`🚀 Server running on http://${HOST}:${PORT}`);
    console.log(`🔐 Admin login: http://${HOST}:${PORT}/admin/login`);
    console.log(`👤 Username: ${process.env.ADMIN_USERNAME || 'Ruhan@0312'}`);
    console.log(`🔑 Password: ${process.env.ADMIN_PASSWORD || 'Ruhan@0312'}`);
    console.log(`🌐 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log('='.repeat(50));
    
    if (process.env.NODE_ENV === 'production') {
        console.log('⚠️  PRODUCTION SETTINGS:');
        console.log('   - Secure cookies: ENABLED');
        console.log('   - Trust proxy: ENABLED');
        console.log('   - Make sure to set SESSION_SECRET in Render environment variables');
    }
});

// ============ ERROR HANDLERS ============
// 404 Error Handler
app.use((req, res) => {
    res.status(404).render('error', { 
        title: 'Page Not Found',
        error: 'The page you are looking for does not exist.' 
    });
});

// Global Error Handler
app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).render('error', { 
        title: 'Server Error',
        error: 'Something went wrong on our end. Please try again later.' 
    });
});
