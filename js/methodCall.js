require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');
const supabaseUrl = 'https://eiwoxrdrysltelcwznyl.supabase.co'; // Your Supabase URL
const supabaseKey = process.env.SUPABASE_KEY; // Your Supabase Key
const supabase = createClient(supabaseUrl, supabaseKey);

const updateMethodCall = async (method, endpoint) => {
    try {
        const { data: methodCalls, error: methodCallError } = await supabase
            .from('method_call')
            .select('*')
            .eq('method', method)
            .eq('endpoint', endpoint);

        if (methodCallError) {
            throw new Error('Error fetching method call data from database');
        }

        if (methodCalls.length > 0) {
            // Row exists, increment request count
            const { error: updateError } = await supabase
                .from('method_call')
                .update({ request: methodCalls[0].request + 1 })
                .eq('method', method)
                .eq('endpoint', endpoint);

            if (updateError) {
                throw new Error('Error updating method call data in database');
            }
        } else {
            // Row does not exist, create a new one
            const { error: insertError } = await supabase
                .from('method_call')
                .insert([{ method: method, endpoint: endpoint, request: 1 }]);

            if (insertError) {
                throw new Error('Error inserting method call data into database');
            }
        }

        return { success: true }; // Return a success object
    } catch (error) {
        console.error(error);
        return { error: error.message }; // Return an error object with the error message
    }
};

module.exports = { updateMethodCall };