require('dotenv').config();

const nodemailer = require("nodemailer");

async function sendEmail(email, code) {

    const html = `
        <div> 
        <h1>Password Recovery</h1>
        <h3>Here is your code: ${code}</h3>
        <p>Use this code to reset your password</p>
        </div>
        `
    ;

    const transporter = nodemailer.createTransport({
        service: "Gmail",
        host: "smtp.gmail.com",
        port: 465,
        secure: true,
        auth: {
            user: process.env.NODEMAILER_EMAIL,
            pass: process.env.NODEMAILER_APPPASSWORD,
        },
    });

    const info = await transporter.sendMail({
        from: `"Personal Website" <${process.env.NODEMAILER_EMAIL}>`,
        to: email,
        subject: `For password reset`,
        html: html,
    });

    console.log("Message sent: %s", info.messageId);
}

module.exports = sendEmail;