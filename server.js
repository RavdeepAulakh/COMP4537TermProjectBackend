const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const path = require('path');

const sendEmail = require("./js/email.js");

const app = express();

const supabaseUrl = 'https://eiwoxrdrysltelcwznyl.supabase.co'; // Your Supabase URL
const supabaseKey = process.env.SUPABASE_KEY; // Your Supabase Key
const supabase = createClient(supabaseUrl, supabaseKey);

app.use(cookieParser());


// Middleware to parse JSON bodies
app.use(bodyParser.json());

// Allow CORS for specified origins
app.use(cors({
    origin: ['http://localhost:3000', 'https://comp4537termproject.netlify.app', 'https://6ceb-142-232-219-53.ngrok-free.app'],
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

        res.status(201).json({ message: 'User signed up successfully' });
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
            res.writeHead(500, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ error: 'Error retrieving user from database' }));
        }

        // If user doesn't exist or password is incorrect
        if (!users || !(await bcrypt.compare(password, users.password))) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ error: 'Invalid email or password' }));
        }

        // Generate JWT token
        const token = jwt.sign({ userId: users.id }, process.env.JWT_SECRET, { expiresIn: '1h' });

        // Set the token as a cookie
        res.writeHead(200, {
            'Set-Cookie': `token=${token}; HttpOnly;`,
            'Content-Type': 'application/json',
          });

        // If login successful
        res.end(JSON.stringify({ message: 'Login successful', userId: users.id, role: users.role, token: token}));
    } catch (error) {
        console.error('Error logging in user:', error.message);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Internal server error' }));
    }
});



// GET route to retrieve user's API calls left
app.get('/api-calls', async (req, res) => {
    // Get user ID from JWT token
    const token = req.headers.cookie.split('=')[1];
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

app.post('/password-recovery', async (req, res) => {
    const { email } = req.body;

    try {
        const { data: user, error } = await supabase
            .from('users')
            .select('id')
            .eq('email', email)
            .single();
        if (error) {
            throw new Error('Error retrieving user from database');
        }

        if (!user) {
            return res.status(404).json({ message: 'Email not registered', success: false });
        }

        const code = Math.floor(100000 + Math.random() * 900000);

        // Update the user's recovery_code in the database
        const { error: insertError } = await supabase
        .from('reset_password')
        .upsert(
            [{ email: email, reset_code: code }],
            { onConflict: ['email'], ignoreDuplicates: false }
        );
    

        await sendEmail(email, code);

        res.json({ message: 'Email sent successfully!', success: true });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Error sending email', success: false });
    }
});


app.post('/verify-code', async (req, res) => {
    const { email, code } = req.body;

    try {
        // Retrieve the user and their reset code
        const { data: userCode, error } = await supabase
            .from('reset_password')
            .select('reset_code')
            .eq('email', email)
            .single();

        

        if (userCode.reset_code != code) {
            return res.status(401).json({ message: 'Invalid code', success: false });
        }
        
        res.json({ message: 'Code verified successfully!', success: true });

    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Error verifying code', success: false });
    }
});


app.patch('/reset-password', async (req, res) => {
    const { email, code, newPassword } = req.body;

    try {
        // Retrieve the user and their recovery code
        const { data: user, error } = await supabase
            .from('users')
            .select('id')
            .eq('email', email)
            .single();


        // Hash the new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        // Update the user's password in the database and clear the recovery code
        const { error: updateError } = await supabase
            .from('users')
            .update({ password: hashedPassword })
            .eq('id', user.id);

        if (updateError) {
            throw new Error('Unable to update password');
        }

        res.json({ message: 'Password has been reset successfully', success: true });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Error resetting password', success: false });
    }
});

app.delete('/delete-row', async (req, res) => {
    const { email } = req.body;

    try {
        // Delete the user's recovery code from the database
        const { error: deleteError } = await supabase
            .from('reset_password')
            .delete()
            .eq('email', email);

        if (deleteError) {
            throw new Error('Unable to delete recovery code');
        }

        res.json({ message: 'Row deleted successfully', success: true });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Error deleting row', success: false });
    }
});




// GET route to retrieve all users' API calls data (accessible only to admin)
app.get('/admin', async (req, res) => {
    // Check if the user is logged in as an admin
    const token = req.headers.cookie.split('=')[1];
    const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
    const userId = decodedToken.userId;

    try {
        // Check if the user is an admin
        const { data: user, error } = await supabase
            .from('users')
            .select('role', 'name')
            .eq('id', userId)
            .single();

        if (error) {
            throw new Error('Error retrieving user information');
        }

        if (!user || user.role !== 'ADMIN') {
            return res.status(403).json({ error: 'Unauthorized access' });
        }

        // Retrieve all users' API calls data from the database
        const { data: allApiCalls, error: apiCallsError } = await supabase
            .from('api_calls')
            .select('user_id, calls');

        if (apiCallsError) {
            throw new Error('Error retrieving API calls data');
        }

        // Fetch usernames for each user ID
        const apiCallsWithUsernames = await Promise.all(
            allApiCalls.map(async (apiCall) => {
                const { data: userData, error: userError } = await supabase
                    .from('users')
                    .select('name')
                    .eq('id', apiCall.user_id)
                    .single();

                if (userError) {
                    throw new Error('Error retrieving username');
                }

                return {
                    username: userData.name,
                    calls: apiCall.calls
                };
            })
        );

        res.status(200).json({ apiCalls: apiCallsWithUsernames });
    } catch (error) {
        console.error('Error retrieving API calls:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// PATCH route to decrement user's API calls by one
app.patch('/v1/api-calls-down', async (req, res) => {
    // Check if the user is logged in as an admin
    const token = req.headers.cookie.split('=')[1];
    const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
    const userId = decodedToken.userId;

    try {
        // Retrieve user's current API calls count from the database
        const { data: userData, error } = await supabase
            .from('api_calls')
            .select('calls')
            .eq('user_id', userId)
            .single();

        if (error) {
            throw new Error('Error retrieving user data');
        }

        // Check if the user has any API calls left
        if (userData.calls === 0) {
            return res.status(403).json({ error: 'No API calls left' });
        }

        // Decrement API calls count by one
        const newCallsCount = userData.calls - 1;

        // Update user's API calls count in the database
        const { updateError } = await supabase
            .from('api_calls')
            .update({ calls: newCallsCount })
            .eq('user_id', userId);

        if (updateError) {
            throw new Error('Error updating API calls count');
        }

        res.status(200).json({ message: 'API calls decremented successfully' });
    } catch (error) {
        console.error('Error decrementing API calls:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// app.use('/v1/docs', express.static(path.join(__dirname, 'html')));

// GET endpoint to serve the index.html file
app.get('/v1/docs', (req, res) => {
    res.sendFile(path.join(__dirname, 'html', 'index.html'));
});

// Start the server
const PORT = process.env.PORT || 8000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
