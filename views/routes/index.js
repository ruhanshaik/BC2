const express = require('express');
const router = express.Router();
const { getPaginatedJobs, getJobById, searchJobs } = require('../models/job');

// Homepage
router.get('/', (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const { jobs, currentPage, totalPages, hasNextPage, hasPrevPage } = getPaginatedJobs(page);
    
    res.render('index', {
        title: 'Bangalore Connect - Find Your Dream Job',
        jobs,
        currentPage,
        totalPages,
        hasNextPage,
        hasPrevPage,
        query: '',
        filters: {}
    });
});

// Job search
router.get('/search', (req, res) => {
    const { q, location, experience, type, page = 1 } = req.query;
    const limit = 10;
    
    const filteredJobs = searchJobs(q, { location, experience, type });
    const startIndex = (page - 1) * limit;
    const endIndex = startIndex + limit;
    const totalPages = Math.ceil(filteredJobs.length / limit);
    
    res.render('index', {
        title: `Search Results - ${q || 'All Jobs'}`,
        jobs: filteredJobs.slice(startIndex, endIndex),
        currentPage: parseInt(page),
        totalPages,
        hasNextPage: endIndex < filteredJobs.length,
        hasPrevPage: startIndex > 0,
        query: q || '',
        filters: { location, experience, type }
    });
});

// Job detail page
router.get('/job/:id', (req, res) => {
    const job = getJobById(req.params.id);
    if (!job) {
        return res.status(404).render('error', { error: 'Job not found' });
    }
    
    res.render('job-detail', {
        title: `${job.title} at ${job.company}`,
        job
    });
});

// WhatsApp redirect
router.get('/whatsapp', (req, res) => {
    res.redirect('https://chat.whatsapp.com/KhTXl9CNMbSG8mv6nYCAAW');
});

// Static pages
router.get('/privacy-policy', (req, res) => {
    res.render('error', { 
        title: 'Privacy Policy',
        error: 'Privacy Policy page coming soon!' 
    });
});

router.get('/terms', (req, res) => {
    res.render('error', { 
        title: 'Terms & Conditions',
        error: 'Terms & Conditions page coming soon!' 
    });
});

module.exports = router;