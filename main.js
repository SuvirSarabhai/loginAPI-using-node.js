const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
require('dotenv').config();
const express = require('express');
const nodemailer = require('nodemailer');

const app = express();
app.use(express.json());

app.use(express.static(__dirname + '/public'));
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/public/login.html');
});
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/public/otp.html');
});
const pool = new Pool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWD,
  database: process.env.DB
});



app.post('/users', async (req, res) => {
  const { email, password } = req.body;
  const insert_query = 'INSERT INTO login (email, password) VALUES ($1, $2)';
  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(insert_query, [email, hashedPassword])

    res.status(201).send("User created");
  } catch (err) {
    console.error("Insert error:", err);
    res.status(500).send("Database error: " + err.message);
  }
});


app.post('/users/login', async (req, res) => {  //authenticate user
  const { email, password } = req.body;
  const find_query = 'SELECT * FROM login WHERE email = $1';
  try {
    const result = await pool.query(find_query, [email])
    if (result.rows.length === 0) {
      return res.status(404).send('User not found');
    }

    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).send('Incorrect password');
    }

    const payload = { email: user.email };
    const token = jwt.sign(payload, process.env.ACCESS_TOKEN, { expiresIn: '1h' });

    const update_query = 'UPDATE login SET token = $1 WHERE email = $2';
    await pool.query(update_query, [token, email]);

    res.status(200).json({
      status: 200,
      message: 'Login successful',
      accessToken: token,
      userEmail: user.email,

    });


  } catch (err) {
    console.error('Login error:', err);
    res.status(500).send('Internal Server Error');
  }
});

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Generate and store OTP
app.post('/users/login/send-otp', async (req, res) => {
  const { email } = req.body;

  try {
    // Verify email exists in database
    const userCheck = await pool.query('SELECT * FROM login WHERE email = $1', [email]);
    if (userCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Email not found' });
    }
    // Generate 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    // Save OTP to database (with expiration - e.g., 15 minutes)
    await pool.query(
      'INSERT INTO otps (email, otp, expires_at) VALUES ($1, $2, NOW() + INTERVAL \'15 minutes\')',
      [email, otp]
    );
    // Send email
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Your Login OTP',
      text: `Your OTP is: ${otp}\nThis code expires in 15 minutes.`
    };
    await transporter.sendMail(mailOptions);
    res.status(200).json({ message: 'OTP sent successfully' });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Failed to send OTP' });
  }
});




app.post('/users/login/verify-otp', async (req, res) => {
  const { email, otp } = req.body;
  try {
    // Find valid OTP
    const result = await pool.query(
      'SELECT * FROM otps WHERE email = $1 AND otp = $2 AND expires_at > NOW()',
      [email, otp]
    );
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid or expired OTP' });
    }
    // Delete the used OTP
    await pool.query('DELETE FROM otps WHERE email = $1 AND otp = $2', [email, otp]);
    res.status(200).json({ message: 'OTP verified successfully' });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Failed to verify OTP' });
  }
});

app.post('/users/verify-passwordresetotp', async (req, res) => {
  const { email, otp } = req.body;
  try {
    // Find valid OTP
    const result = await pool.query(
      'SELECT * FROM password_reset_otps WHERE email = $1 AND otp = $2 AND expires_at > NOW()',
      [email, otp]
    );
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid or expired OTP' });
    }
    // Delete the used OTP
    await pool.query('DELETE FROM password_reset_otps WHERE email = $1 AND otp = $2', [email, otp]);
    res.status(200).json({ message: 'OTP verified successfully' });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Failed to verify OTP' });
  }
});

app.post('/users/login/resend-otp', async (req, res) => {
  const { email } = req.body
  try {

    await pool.query('DELETE FROM otps WHERE email = $1', [email]);


    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    await pool.query(
      'INSERT INTO otps (email, otp, expires_at) VALUES ($1, $2, NOW() + INTERVAL \'15 minutes\')',
      [email, otp]
    );

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Your Login OTP',
      text: `Your new OTP is: ${otp}\nThis code expires in 15 minutes.`
    };
    await transporter.sendMail(mailOptions);
    res.status(200).json({ message: 'New OTP sent successfully' });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Failed to resend OTP' });
  }
})


app.post('/users/forgot-password', async (req, res) => {
  const { email } = req.body;
  try {

    const userCheck = await pool.query('SELECT * FROM login WHERE email = $1', [email]);
    if (userCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Email not found' });
    }
    // Generate 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    await pool.query(
      'INSERT INTO password_reset_otps (email, otp, expires_at) VALUES ($1, $2, NOW() + INTERVAL \'15 minutes\')',
      [email, otp]
    );
    // Send email
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Password reset OTP',
      text: `Your OTP for password reset is: ${otp}\nThis code expires in 15 minutes.`
    };
    await transporter.sendMail(mailOptions);
    res.status(200).json({ message: 'OTP sent successfully' });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Failed to send OTP' });
  }
});

app.post('/users/reset-password', async (req, res) => {
  const { email, newPassword, otp } = req.body
  try {
    const result = await pool.query(
      'SELECT * FROM password_reset_otps WHERE email = $1 AND otp = $2 AND expires_at > NOW()',
      [email, otp]
    );
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid or expired OTP' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update user password in database
    await pool.query('UPDATE login SET password = $1 WHERE email = $2', [hashedPassword, email]);

    //  Delete used OTP
    await pool.query('DELETE FROM password_reset_otps WHERE email = $1 AND otp = $2', [email, otp]);

    res.status(200).json({ message: 'Password reset successful' });

  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ error: 'Failed to reset password' });
  }
});




app.listen(3000, () => {
  console.log("Server is running on port 3000...");
});
