const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const path = require('path');
const { updateMethodCall } = require("./js/methodCall.js");
const { addRequestToUser } = require("./js/addRequestToUser.js");
const sendEmail = require("./js/email.js");

const app = express();

const supabaseUrl = 'https://eiwoxrdrysltelcwznyl.supabase.co'; // Your Supabase URL
const supabaseKey = process.env.SUPABASE_KEY; // Your Supabase Key
const supabase = createClient(supabaseUrl, supabaseKey);
const messages = require('./messages/en/strings.js');

app.use(cookieParser());


// Middleware to parse JSON bodies
app.use(bodyParser.json());

// Allow CORS for specified origins
app.use(cors({
    origin: ['https://comp4537termproject.netlify.app'],
    credentials: true,
    exposedHeaders: ["set-cookie"]
}));

// POST route for sign up
app.post('/v1/signup', async (req, res) => {
    const { name, email, password } = req.body;

    try {
        // Check if the user already exists
        const { data: existingUser } = await supabase
            .from('users')
            .select('id')
            .eq('email', email)
            .single();

        if (existingUser) {
            return res.status(400).json({ error: messages.userAlreadyExists });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert the user into the database
        const { data: newUser, error } = await supabase.from('users').insert([
            { name, email, password: hashedPassword },
        ]).select('id');

        // Insert the user role into the users_role table
        const { error: roleError } = await supabase.from('users_role').insert([
            { id: newUser[0].id, role: 'USER' },
        ]);

        if (roleError) {
            throw new Error(messages.errorAssigningRole);
        }

        // Insert initial api_calls record for the user
        await supabase.from('api_calls').insert([
            { user_id: newUser[0].id, calls: 20 },
        ]);

        const methodCallResult = updateMethodCall('POST', '/v1/signup');

        if (methodCallResult.error) {
            console.error('Error updating method call:', methodCallResult.error);
            // Decide how you want to handle this error
        }

        res.status(201).json({ message: messages.signUpSuccess });
    } catch (error) {
        console.error('Error signing up user:', error.message);
        res.status(500).json({ error: messages.internalServerError });
    }
});


// POST route for login
app.post('/v1/login', async (req, res) => {
    console.log('Logging in called')
    const { email, password } = req.body;

    try {
        // Retrieve the user and their role from the database
        const { data: user, error } = await supabase
            .from('users')
            .select('id, email, password, users_role(role)')
            .eq('email', email)
            .single();

        if (error) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ error: messages.errorRetrievingUser }));
        }

        // If user doesn't exist or password is incorrect
        if (!user || !(await bcrypt.compare(password, user.password))) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ error: messages.invalidEmailOrPassword }));
        }

        // Generate JWT token
        const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });

        // Set the token as a cookie
        res.writeHead(200, {
            'Set-Cookie': `token=${token}; HttpOnly; SameSite=None; Secure;`,
            'Content-Type': 'application/json',
        });

        const methodCallResult = await updateMethodCall('POST', '/v1/login');

        if (methodCallResult.error) {
            console.error('Error updating method call:', methodCallResult.error);
            // Decide how you want to handle this error
        }

        // Update the total request count for the user
        const requestResult = await addRequestToUser(user.id, email);
        if (requestResult.error) {
            console.error('Error updating user request count:', requestResult.error);
            // Decide how you want to handle this error
        }

        // If login successful
        res.end(JSON.stringify({ message: messages.loginSuccess, userId: user.id, role: user.users_role.role, token: token}));
    } catch (error) {
        console.error('Error logging in user:', error.message);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: messages.internalServerError }));
    }
});

// POST route for logout
app.post('/v1/logout', (req, res) => {
    console.log('Logging out');

    const allowedOrigins = ['https://comp4537termproject.netlify.app'];
    const origin = req.headers.origin;

    try {
        // Set the token cookie to an empty value with an immediate expiration date
        res.setHeader('Set-Cookie', 'token=; HttpOnly; SameSite=None; Secure; Expires=Thu, 01 Jan 1970 00:00:00 GMT');

        // Check if the request's origin is in the allowedOrigins array and set the Access-Control-Allow-Origin header accordingly
        if (allowedOrigins.includes(origin)) {
            res.setHeader('Access-Control-Allow-Origin', origin);
        }

        // Send a response indicating logout was successful
        res.status(200).json({ message: messages.logoutSuccess });
    } catch (error) {
        console.error('Error logging out user:', error.message);
        res.status(500).json({ error: messages.internalServerError });
    }
});




// GET route to retrieve user's API calls left
app.get('/v1/api-calls', async (req, res) => {
    try {
        const methodCallResult = await updateMethodCall('GET', '/v1/api-calls');
        if (methodCallResult.error) {
            console.error(messages.errorUpdatingMethodCall, methodCallResult.error);
            // Decide how you want to handle this error
        }

        // Get user ID from JWT token
        const token = req.headers.cookie.split('=')[1];
        const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
        const userId = decodedToken.userId;

        const requestResult = await addRequestToUser(userId, decodedToken.email);
        if (requestResult.error) {
            console.error(messages.errorUpdatingUserRequestCount, requestResult.error);
            // Decide how you want to handle this error
        }

        // Retrieve user's API calls left from the database
        const { data: apiCalls } = await supabase
            .from('api_calls')
            .select('calls')
            .eq('user_id', userId)
            .single();

        res.status(200).json({ calls: apiCalls.calls });
    } catch (error) {
        console.error(messages.errorRetrievingAPICalls, error.message);
        res.status(500).json({ error: messages.internalServerError });
    }
});

app.post('/v1/password-recovery', async (req, res) => {
    try {
        const methodCallResult = await updateMethodCall('POST', '/v1/password-recovery');
        if (methodCallResult.error) {
            console.error(messages.errorUpdatingMethodCall, methodCallResult.error);
            // Decide how you want to handle this error
        }

        const { email } = req.body;

        const { data: user, error } = await supabase
            .from('users')
            .select('id')
            .eq('email', email)
            .single();
        if (error) {
            throw new Error(messages.errorRetrievingUser);
        }

        if (!user) {
            return res.status(404).json({ message: messages.emailNotRegistered, success: false });
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

        res.json({ message: messages.emailSentSuccessfully, success: true });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: messages.errorSendingEmail, success: false });
    }
});


app.post('/v1/verify-code', async (req, res) => {
    try {
        const methodCallResult = await updateMethodCall('POST', '/v1/verify-code');
        if (methodCallResult.error) {
            console.error(messages.errorUpdatingMethodCall, methodCallResult.error);
            // Decide how you want to handle this error
        }

        const { email, code } = req.body;

        // Retrieve the user and their reset code
        const { data: userCode, error } = await supabase
            .from('reset_password')
            .select('reset_code')
            .eq('email', email)
            .single();

        if (error) {
            throw new Error(messages.errorVerifyingCode);
        }

        if (userCode.reset_code !== code) {
            return res.status(401).json({ message: messages.invalidCode, success: false });
        }

        res.json({ message: messages.codeVerifiedSuccessfully, success: true });

    } catch (error) {
        console.error(error);
        res.status(500).json({ message: messages.errorVerifyingCode, success: false });
    }
});


app.patch('/v1/reset-password', async (req, res) => {
    try {
        const methodCallResult = await updateMethodCall('PATCH', '/v1/reset-password');
        if (methodCallResult.error) {
            console.error(messages.errorUpdatingMethodCall, methodCallResult.error);
            // Decide how you want to handle this error
        }

        const { email, code, newPassword } = req.body;

        // Retrieve the user and their recovery code
        const { data: user, error } = await supabase
            .from('users')
            .select('id')
            .eq('email', email)
            .single();

        if (error) {
            throw new Error(messages.errorResettingPassword);
        }

        // Hash the new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        // Update the user's password in the database and clear the recovery code
        const { error: updateError } = await supabase
            .from('users')
            .update({ password: hashedPassword })
            .eq('id', user.id);

        if (updateError) {
            throw new Error(messages.unableToUpdatePassword);
        }

        res.json({ message: messages.passwordResetSuccessfully, success: true });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: messages.errorResettingPassword, success: false });
    }
});

app.delete('/v1/delete-row', async (req, res) => {
    try {
        const methodCallResult = await updateMethodCall('DELETE', '/v1/delete-row');
        if (methodCallResult.error) {
            console.error(messages.errorUpdatingMethodCall, methodCallResult.error);
            // Decide how you want to handle this error
        }

        const { email } = req.body;

        // Delete the user's recovery code from the database
        const { error: deleteError } = await supabase
            .from('reset_password')
            .delete()
            .eq('email', email);

        if (deleteError) {
            throw new Error(messages.unableToDeleteRecoveryCode);
        }

        res.json({ message: messages.rowDeletedSuccessfully, success: true });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: messages.errorDeletingRow, success: false });
    }
});

app.get('/v1/admin', async (req, res) => {
    try {
        const token = req.headers.cookie.split('=')[1];
        const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
        const userId = decodedToken.userId;

        const { data: userRole, error } = await supabase
            .from('users')
            .select('users_role(role)')
            .eq('id', userId)
            .single();

        if (error) {
            throw new Error(messages.errorRetrievingUserInfo);
        }

        if (!userRole || userRole.users_role.role !== 'ADMIN') {
            return res.status(403).json({ error: messages.unauthorizedAccess });
        }

        const { data: allApiCalls, error: apiCallsError } = await supabase
            .from('api_calls')
            .select('user_id, calls');

        if (apiCallsError) {
            throw new Error(messages.errorRetrievingAPICallsData);
        }

        const { data: allUserTotalCalls, error: userTotalCallsError } = await supabase
            .from('user_total_call')
            .select('*');

        if (userTotalCallsError) {
            throw new Error(messages.errorRetrievingUserTotalCallsData);
        }

        const { data: allMethodCalls, error: methodCallsError } = await supabase
            .from('method_call')
            .select('*');

        if (methodCallsError) {
            throw new Error(messages.errorRetrievingMethodCallsData);
        }

        const apiCallsWithUsernames = await Promise.all(
            allApiCalls.map(async (apiCall) => {
                const { data: userData, error: userError } = await supabase
                    .from('users')
                    .select('name')
                    .eq('id', apiCall.user_id)
                    .single();

                if (userError) {
                    throw new Error(messages.errorRetrievingUsername);
                }

                return {
                    username: userData.name,
                    calls: apiCall.calls
                };
            })
        );

        const response = {
            apiCalls: apiCallsWithUsernames,
            totalCalls: allUserTotalCalls,
            methodCalls: allMethodCalls
        };

        console.log('Response:', response);

        const requestResult = await addRequestToUser(userId, decodedToken.email);
        if (requestResult.error) {
            console.error('Error updating user request count:', requestResult.error);
            // Decide how you want to handle this error
        }

        const methodCallResult = await updateMethodCall('GET', '/v1/admin');

        if (methodCallResult.error) {
            console.error(messages.errorUpdatingMethodCall, methodCallResult.error);
            // Decide how you want to handle this error
        }

        res.status(200).json(response);
    } catch (error) {
        console.error('Error:', error.message);
        res.status(500).json({ error: messages.internalServerError });
    }
});

app.patch('/v1/api-calls-down', async (req, res) => {
    try {
        const methodCallResult = await updateMethodCall('PATCH', '/v1/api-calls-down');

        if (methodCallResult.error) {
            console.error('Error updating method call:', methodCallResult.error);
            // Decide how you want to handle this error
        }

        const token = req.headers.cookie.split('=')[1];
        const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
        const userId = decodedToken.userId;

        const { data: userData, error } = await supabase
            .from('api_calls')
            .select('calls')
            .eq('user_id', userId)
            .single();

        if (error) {
            throw new Error(messages.errorRetrievingUserData);
        }

        if (userData.calls === 0) {
            return res.status(403).json({ error: messages.noAPICallsLeft });
        }

        const newCallsCount = userData.calls - 1;

        const { updateError } = await supabase
            .from('api_calls')
            .update({ calls: newCallsCount })
            .eq('user_id', userId);

        if (updateError) {
            throw new Error(messages.errorUpdatingAPICallsCount);
        }

        res.status(200).json({ message: 'API calls decremented successfully' });
    } catch (error) {
        console.error('Error decrementing API calls:', error.message);
        res.status(500).json({ error: messages.internalServerError });
    }
});

// app.use('/v1/docs', express.static(path.join(__dirname, 'html')));

// GET endpoint to serve the index.html file
app.get('/v1/docs', (req, res) => {
    const methodCallResult = updateMethodCall('GET', '/v1/docs');

    if (methodCallResult.error) {
        console.error('Error updating method call:', methodCallResult.error);
        // Decide how you want to handle this error
    }

    res.sendFile(path.join(__dirname, 'html', 'index.html'));
});

// Start the server
const PORT = process.env.PORT || 8000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
