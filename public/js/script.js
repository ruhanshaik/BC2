// Toast Notification System
class Toast {
    static show(message, type = 'info', duration = 3000) {
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.innerHTML = `
            <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'info-circle'}"></i>
            <span>${message}</span>
        `;
        
        document.body.appendChild(toast);
        
        // Show toast
        setTimeout(() => {
            toast.classList.add('show');
        }, 10);
        
        // Hide and remove toast
        setTimeout(() => {
            toast.classList.remove('show');
            setTimeout(() => {
                document.body.removeChild(toast);
            }, 300);
        }, duration);
    }
}

// Job Sharing
function shareJob(jobId) {
    const jobUrl = `${window.location.origin}/job/${jobId}`;
    
    if (navigator.share) {
        navigator.share({
            title: 'Check out this job opportunity!',
            text: 'I found this interesting job on Bangalore Connect',
            url: jobUrl,
        })
        .then(() => Toast.show('Job shared successfully!', 'success'))
        .catch((error) => console.log('Error sharing:', error));
    } else {
        // Fallback: Copy to clipboard
        navigator.clipboard.writeText(jobUrl)
            .then(() => Toast.show('Link copied to clipboard!', 'success'))
            .catch(() => {
                // Last resort: Open share dialog
                window.open(`https://twitter.com/intent/tweet?text=Check out this job opportunity!&url=${encodeURIComponent(jobUrl)}`, '_blank');
            });
    }
}

// Save Job
function saveJob(jobId) {
    const savedJobs = JSON.parse(localStorage.getItem('savedJobs') || '[]');
    const btn = event.currentTarget;
    
    if (savedJobs.includes(jobId)) {
        // Remove from saved
        const index = savedJobs.indexOf(jobId);
        savedJobs.splice(index, 1);
        btn.innerHTML = '<i class="far fa-bookmark"></i>';
        btn.classList.remove('saved');
        Toast.show('Job removed from saved', 'info');
    } else {
        // Add to saved
        savedJobs.push(jobId);
        btn.innerHTML = '<i class="fas fa-bookmark"></i>';
        btn.classList.add('saved');
        Toast.show('Job saved successfully!', 'success');
    }
    
    localStorage.setItem('savedJobs', JSON.stringify(savedJobs));
}

// Initialize saved jobs state
document.addEventListener('DOMContentLoaded', function() {
    // Check saved jobs and update UI
    const savedJobs = JSON.parse(localStorage.getItem('savedJobs') || '[]');
    document.querySelectorAll('.save-btn').forEach(btn => {
        const jobId = btn.getAttribute('onclick')?.match(/\d+/)?.[0];
        if (jobId && savedJobs.includes(parseInt(jobId))) {
            btn.innerHTML = '<i class="fas fa-bookmark"></i>';
            btn.classList.add('saved');
        }
    });
    
    // Auto-refresh CAPTCHA
    const refreshBtn = document.querySelector('.refresh-captcha');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', function(e) {
            e.preventDefault();
            const captchaBox = document.querySelector('.captcha-box');
            if (captchaBox) {
                captchaBox.textContent = generateCaptcha();
                document.querySelector('input[name="captchaHidden"]').value = captchaBox.textContent;
            }
        });
    }
    
    // Form validation for admin login
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', function(e) {
            const captchaInput = document.querySelector('input[name="captcha"]');
            const captchaHidden = document.querySelector('input[name="captchaHidden"]');
            
            if (captchaInput && captchaHidden && captchaInput.value !== captchaHidden.value) {
                e.preventDefault();
                Toast.show('Please enter the correct CAPTCHA', 'error');
            }
        });
    }
});

// Generate CAPTCHA (client-side fallback)
function generateCaptcha() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let captcha = '';
    for (let i = 0; i < 6; i++) {
        captcha += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return captcha;
}

// Smooth scroll
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({
                behavior: 'smooth',
                block: 'start'
            });
        }
    });
});