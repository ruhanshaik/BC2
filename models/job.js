class Job {
    constructor(id, title, company, location, type, experience, postedDate, description, salary) {
        this.id = id;
        this.title = title;
        this.company = company;
        this.location = location;
        this.type = type; // 'Full-time', 'Part-time', 'Remote', 'Internship'
        this.experience = experience; // 'Fresher', '1-2 years', '2-4 years', '3-5 years', '5+ years'
        this.postedDate = postedDate;
        this.description = description;
        this.salary = salary;
    }

    getShortDescription() {
        return this.description.length > 120 
            ? this.description.substring(0, 120) + '...' 
            : this.description;
    }

    formatDate() {
        const date = new Date(this.postedDate);
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
}

// Sample jobs data
const jobs = [
    new Job(
        1,
        'Full Stack Developer',
        'Tech Solutions Inc',
        'Bangalore',
        'Full-time',
        '2-4 years',
        new Date('2024-01-15'),
        'We are looking for a skilled Full Stack Developer with experience in Node.js, React, and MongoDB. You will be responsible for developing and maintaining web applications, collaborating with cross-functional teams, and implementing new features.',
        '₹8-12 LPA'
    ),
    new Job(
        2,
        'Software Engineer',
        'Innovate Tech',
        'Bangalore',
        'Full-time',
        'Fresher',
        new Date('2024-01-18'),
        'Exciting opportunity for fresh graduates to join our dynamic software engineering team. Training will be provided. Strong problem-solving skills and knowledge of programming fundamentals required.',
        '₹4-6 LPA'
    ),
    new Job(
        3,
        'DevOps Engineer',
        'Cloud Systems',
        'Remote',
        'Full-time',
        '3-5 years',
        new Date('2024-01-10'),
        'Looking for DevOps Engineer with expertise in AWS, Docker, Kubernetes, and CI/CD pipelines. You will be responsible for infrastructure management and deployment automation.',
        '₹12-18 LPA'
    ),
    new Job(
        4,
        'Frontend Developer',
        'Digital Creations',
        'Bangalore',
        'Full-time',
        '1-3 years',
        new Date('2024-01-20'),
        'Join our UI/UX team to create amazing user interfaces using React.js, TypeScript, and modern CSS frameworks. Experience with responsive design is a must.',
        '₹6-10 LPA'
    ),
    new Job(
        5,
        'Data Scientist',
        'Analytics Pro',
        'Bangalore',
        'Full-time',
        '3-5 years',
        new Date('2024-01-12'),
        'Seeking Data Scientist with expertise in Python, Machine Learning, and statistical analysis. Experience with TensorFlow or PyTorch is preferred.',
        '₹10-15 LPA'
    ),
    new Job(
        6,
        'Backend Developer',
        'Server Masters',
        'Bangalore',
        'Full-time',
        '2-4 years',
        new Date('2024-01-16'),
        'Looking for Backend Developer proficient in Node.js, Python, and database design. Experience with microservices architecture is a plus.',
        '₹9-13 LPA'
    ),
    new Job(
        7,
        'Mobile App Developer',
        'App Innovators',
        'Hybrid',
        'Full-time',
        '1-2 years',
        new Date('2024-01-19'),
        'Develop cross-platform mobile applications using React Native. Knowledge of iOS and Android development is beneficial.',
        '₹5-8 LPA'
    ),
    new Job(
        8,
        'UI/UX Designer',
        'Design Studio',
        'Bangalore',
        'Full-time',
        '2-4 years',
        new Date('2024-01-14'),
        'Creative UI/UX Designer needed to design intuitive user interfaces. Proficiency in Figma, Adobe XD, and prototyping tools required.',
        '₹7-11 LPA'
    ),
    new Job(
        9,
        'QA Engineer',
        'Quality First',
        'Bangalore',
        'Full-time',
        '1-3 years',
        new Date('2024-01-17'),
        'Quality Assurance Engineer with experience in manual and automated testing. Knowledge of Selenium or Cypress is preferred.',
        '₹5-8 LPA'
    ),
    new Job(
        10,
        'Product Manager',
        'Product Leaders',
        'Bangalore',
        'Full-time',
        '5+ years',
        new Date('2024-01-11'),
        'Experienced Product Manager to lead product development and strategy. Strong leadership and communication skills required.',
        '₹18-25 LPA'
    )
];

// Get paginated jobs
const getPaginatedJobs = (page = 1, limit = 10) => {
    const startIndex = (page - 1) * limit;
    const endIndex = startIndex + limit;
    const totalPages = Math.ceil(jobs.length / limit);
    
    return {
        jobs: jobs.slice(startIndex, endIndex),
        currentPage: page,
        totalPages,
        hasNextPage: endIndex < jobs.length,
        hasPrevPage: startIndex > 0
    };
};

// Get job by ID
const getJobById = (id) => {
    return jobs.find(job => job.id === parseInt(id));
};

// Search jobs
const searchJobs = (query, filters = {}) => {
    return jobs.filter(job => {
        const matchesQuery = !query || 
            job.title.toLowerCase().includes(query.toLowerCase()) ||
            job.company.toLowerCase().includes(query.toLowerCase()) ||
            job.description.toLowerCase().includes(query.toLowerCase());
        
        const matchesLocation = !filters.location || 
            job.location.toLowerCase().includes(filters.location.toLowerCase());
        
        const matchesExperience = !filters.experience || 
            job.experience === filters.experience;
        
        const matchesType = !filters.type || 
            job.type === filters.type;
        
        return matchesQuery && matchesLocation && matchesExperience && matchesType;
    });
};

module.exports = {
    Job,
    getPaginatedJobs,
    getJobById,
    searchJobs
};