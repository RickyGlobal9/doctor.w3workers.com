const express = require("express");
const path = require("path");
const fs = require('fs').promises;
const bcrypt = require('bcryptjs');
const session = require('express-session');

const app = express();
const PORT = 3000;
const app_version = 1.0;
const ROUNDS = 10;
const SALT = bcrypt.genSaltSync(ROUNDS);

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// EJS engine
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.static(path.join(__dirname, "public")));

// Routes
// As of now there is no home page so redirect to signin page
app.get('/', (req, res) => {
    res.redirect('/signin')
});

app.get('/signin', (req, res) => {
    res.render("signin", { title: `Admin Panel v${app_version}`, page: 'signin' });
});

// If incorrectly passed then redirect to dashboard
app.get('/admin', (req, res) => {
    res.redirect('/admin/dashboard')
});

app.get('/admin/dashboard', (req, res) => {
    res.render("dashboard", { title: `Admin Panel v${app_version}`, page: 'dashboard' });
});

app.get('/admin/users', (req, res) => {
    res.render("users", { title: `Admin Panel v${app_version}`, page: 'users' });
});

app.get('/admin/add-user', (req, res) => {
    res.render("add-user", { title: `Admin Panel v${app_version}`, page: 'add user' });
});

app.get('/admin/settings', (req, res) => {
    res.render("settings", { title: `Admin Panel v${app_version}`, page: 'settings' });
});

// Api & Endpoints
app.post('/adduser', async (req, res) => {
    const { fname, lname, email, mobile, new_pass } = req.body;

    try {
        // Reads existing users
        let users = [];
        try {
            const data = await fs.readFile('./user_data/users.json', 'utf8');
            users = JSON.parse(data);
        } catch (error) {
            if (error.code !== 'ENOENT') throw error;
        }

        // Generates unique slno
        const maxSlno = users.length > 0 ? Math.max(...users.map(user => user.slno)) : 0;
        const newSlno = maxSlno + 1;

        // Hashed password
        const hash = await bcrypt.hash(new_pass, SALT);

        // Creates new user
        const newUser = {
            slno: newSlno,
            creation: new Date().toISOString(),
            fname,
            lname,
            email,
            mobile,
            hash,
            status: 'pending'
        };

        // Appends to file
        users.push(newUser);
        await fs.writeFile('./user_data/users.json', JSON.stringify(users, null, 2));

        res.json(1)
    } catch (error) {
        console.error('Error adding user:', error);
        res.json(0);
    }
});

app.get('/getusers', async (req, res) => {
    try {
        const data = await fs.readFile('./user_data/users.json', 'utf8');
        const users = JSON.parse(data);

        // Sorts users by slno in descending order
        users.sort((a, b) => b.slno - a.slno);
        res.json(users);
    } catch (error) {
        console.error('Error retrieving users:', error);
        res.status(500).json({ error: 'Error retrieving users' });
    }
});

// 404 Error Handler
app.use((req, res) => {
    res.status(404).render("404", { title: `404 Not Found - Admin Panel v${app_version}`, page: '404' });
});

// Start Server
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

async function test() {
    const hash = await bcrypt.hash('admin@123', SALT);
    console.log(hash)

    const isValid = await bcrypt.compare('admin@123', hash);
    console.log(isValid)
}
// test()