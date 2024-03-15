const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const supabaseUrl = 'https://eiwoxrdrysltelcwznyl.supabase.co'; // Your Supabase URL
const supabaseKey = process.env.SUPABASE_KEY; // Your Supabase Key
const supabase = createClient(supabaseUrl, supabaseKey);

// Middleware to parse JSON bodies
app.use(bodyParser.json());

// Allow CORS for specified origins
app.use(cors({
    origin: ['http://localhost:3000', 'https://comp4537termproject.netlify.app'],
    credentials: true
}));


// POST route for sign up
app.post('/signup', async (req, res) => {
    const { name, email, password } = req.body;

    try {
        // Check if the user already exists
        const { data: existingUser } = await supabase
            .from('users')
            .select('id')
            .eq('email', email)
            .single();

        if (existingUser) {
            return res.status(400).json({ error: 'User already exists' });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert the user into the database
        const { data: newUser, error } = await supabase.from('users').insert([
            { name, email, password: hashedPassword, role: 'USER'},
        ]).select('id, role');

        // Insert initial api_calls record for the user
        await supabase.from('api_calls').insert([
            { user_id: newUser[0].id, calls: 20 },
        ]);

        // Generate JWT token
        const token = jwt.sign({ userId: newUser.id }, process.env.JWT_SECRET, { expiresIn: '1h' });

        // Set the token as a cookie
        res.cookie('token', token, { httpOnly: true });

        res.status(201).json({ message: 'User signed up successfully', userId: newUser[0].id, role: newUser[0].role });
    } catch (error) {
        console.error('Error signing up user:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// POST route for login
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        // Retrieve the user from the database
        const { data: users, error } = await supabase
            .from('users')
            .select('id, email, password, role')
            .eq('email', email)
            .single();

        if (error) {
            return res.status(500).json({ error: 'Error retrieving user from database' });
        }

        // If user doesn't exist or password is incorrect
        if (!users || !(await bcrypt.compare(password, users.password))) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        // Generate JWT token
        const token = jwt.sign({ userId: users.id }, process.env.JWT_SECRET, { expiresIn: '1h' });

        // Set the token as a cookie
        res.cookie('token', token, { httpOnly: true });

        // If login successful
        res.status(200).json({ message: 'Login successful', userId: users.id, role: users.role});
    } catch (error) {
        console.error('Error logging in user:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// GET route to retrieve user's API calls left
app.get('/api-calls', async (req, res) => {
    // Get user ID from JWT token
    const token = req.headers.authorization.split(' ')[1];
    const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
    const userId = decodedToken.userId;

    try {
        // Retrieve user's API calls left from the database
        const { data: apiCalls } = await supabase
            .from('api_calls')
            .select('calls')
            .eq('user_id', userId)
            .single();

        res.status(200).json({ calls: apiCalls.calls });
    } catch (error) {
        console.error('Error retrieving API calls:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});


// Start the server
const PORT = process.env.PORT || 8000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
