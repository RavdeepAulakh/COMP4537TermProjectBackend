require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');
const supabaseUrl = 'https://eiwoxrdrysltelcwznyl.supabase.co'; // Your Supabase URL
const supabaseKey = process.env.SUPABASE_KEY; // Your Supabase Key
const supabase = createClient(supabaseUrl, supabaseKey);

const addRequestToUser = async (userId, email) => {
    console.log('Adding request to user:', userId, email)
    try {
        const { data: userTotalCalls, error: userTotalCallError } = await supabase
            .from('user_total_call')
            .select('total_request')
            .eq('id', userId);

        if (userTotalCallError) {
            console.error('Supabase error:', userTotalCallError.message);
            throw new Error('Error retrieving user total call data');
        }

        let newRequestCount;
        if (userTotalCalls.length > 0) {
            // User exists, increment request count
            const userTotalCall = userTotalCalls[0]; // Assuming 'id' is unique, there should be only one row
            newRequestCount = userTotalCall.total_request + 1;
            const { error: updateError } = await supabase
                .from('user_total_call')
                .update({ total_request: newRequestCount })
                .eq('id', userId);

            if (updateError) {
                throw new Error('Error updating user total call count');
            }
        } else {
            // User does not exist, create a new entry
            newRequestCount = 1;
            const { error: insertError } = await supabase
                .from('user_total_call')
                .insert([{ id: userId, email: email, total_request: newRequestCount }]);

            if (insertError) {
                console.error('Supabase insertion error:', insertError.message, insertError.details);
                throw new Error('Error inserting user total call data into database');
            }
        }

        return { success: true, requestCount: newRequestCount };
    } catch (error) {
        console.error(error);
        return { error: error.message };
    }
};

module.exports = { addRequestToUser };