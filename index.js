const
    express = require("express"),
    path = require("path"),
    fs = require('fs').promises,
    bcrypt = require('bcryptjs'),
    session = require('express-session'),
    logEvent = require('./logEvent'),
    axios = require('axios');

const app = express(),
    PORT = 2003,
    app_version = 1.0,
    ROUNDS = 10,
    SALT = bcrypt.genSaltSync(ROUNDS);

//Creates session for 24 hours
app.use(session({
    secret: 'A6B2D0U1L4R3A8Z1I6Q5UE',
    saveUninitialized: true,
    cookie: { maxAge: 1000 * 60 * 60 * 24 },
    resave: false
}));

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
    const _SESSION = req.session;
    if (_SESSION.userId) {
        res.redirect('/admin');
    }
    else {
        res.render("signin", { title: `Admin Panel v${app_version}`, page: 'signin' });
    }
});

app.post('/userlogin', async (req, res) => {
    const
        _SESSION = req.session,
        { email, password } = req.body;

    try {
        const
            data = await fs.readFile('./user_data/users.json', 'utf8'),
            users = JSON.parse(data),
            user = users.find(user => user.email === email),
            isValid = await bcrypt.compare(password, user.hash);

        if (isValid == true) {
            _SESSION.userId = user.slno;
            _SESSION.fName = user.fname;
            await logEvent({ user_id: _SESSION.userId, event: 'login', status: 'success' });
            res.json(1)
        }
        else {
            res.json(0)
        }

    } catch (error) {
        res.json(0)
        console.log('login error:', error.message);
    }
})

app.get('/logout', async (req, res) => {
    const _SESSION = req.session;
    await logEvent({ user_id: _SESSION.userId, event: 'logout', status: 'success' });
    req.session.destroy();
    res.json(1).end()
});

// If incorrectly passed then redirect to dashboard
app.get('/admin', (req, res) => {
    const _SESSION = req.session;
    if (_SESSION.userId) {
        res.render("dashboard", { title: `Admin Panel v${app_version}`, page: 'dashboard', fname: _SESSION.fName });
    }
    else {
        res.redirect('/signin');
    }
});

app.get('/admin/dashboard', (req, res) => {
    const _SESSION = req.session;
    if (_SESSION.userId) {
        res.render("dashboard", { title: `Admin Panel v${app_version}`, page: 'dashboard', fname: _SESSION.fName });
    }
    else {
        res.redirect('/signin');
    }
});

app.get('/admin/users', (req, res) => {
    const _SESSION = req.session;
    if (_SESSION.userId) {
        res.render("users", { title: `Admin Panel v${app_version}`, page: 'users', fname: _SESSION.fName });
    }
    else {
        res.redirect('/signin');
    }
});

app.get('/admin/add-user', (req, res) => {
    const _SESSION = req.session;
    if (_SESSION.userId) {
        res.render("add-user", { title: `Admin Panel v${app_version}`, page: 'add-user', fname: _SESSION.fName });
    }
    else {
        res.redirect('/signin');
    }
});

app.get('/admin/settings', (req, res) => {
    const _SESSION = req.session;
    if (_SESSION.userId) {
        res.render("settings", { title: `Admin Panel v${app_version}`, page: 'settings', fname: _SESSION.fName });
    }
    else {
        res.redirect('/signin');
    }
});

app.get('/admin/logs', (req, res) => {
    const _SESSION = req.session;
    if (_SESSION.userId) {
        res.render("logs", { title: `Admin Panel v${app_version}`, page: 'logs', fname: _SESSION.fName });
    }
    else {
        res.redirect('/signin');
    }
});

// Api & Endpoints
app.post('/changepassword', async (req, res) => {
    const _SESSION = req.session;
    if (!_SESSION.userId) {
        console.log('Unauthorized access attempt');
        return res.json({ error: 'Unauthorized access' });
    }
    const { current_pass, new_pass } = req.body;
    console.log(current_pass, new_pass)

    try {
        // Retrieves existing users
        let users = [];
        try {
            const data = await fs.readFile('./user_data/users.json', 'utf8');
            users = JSON.parse(data);
        } catch (error) {
            if (error.code !== 'ENOENT') throw error;
        }

        // Finds user by slno
        const userIndex = users.findIndex(user => user.slno === parseInt(_SESSION.userId));
        if (userIndex === -1) {
            console.log('User not found', _SESSION.userId);
            return res.json(0);
        }
        const isValid = await bcrypt.compare(current_pass, users[userIndex].hash);
        if (isValid == true) {
            // Updates user data
            const updatedHash = {
                slno: users[userIndex].slno,
                creation: users[userIndex].creation,
                fname: users[userIndex].fname,
                lname: users[userIndex].lname,
                email: users[userIndex].email,
                mobile: users[userIndex].mobile,
                hash: new_pass && new_pass.trim() ? await bcrypt.hash(new_pass, SALT) : users[userIndex].hash,
                status: users[userIndex].status
            };

            // Writes back to file
            users[userIndex] = updatedHash;
            await fs.writeFile('./user_data/users.json', JSON.stringify(users, null, 2));
            await logEvent({ user_id: _SESSION.userId, event: 'password change', status: 'success' });
            res.json(1);
        }
        else {
            await logEvent({ user_id: _SESSION.userId, event: 'password change', status: 'failure' });
            res.json(0)
        }
    } catch (error) {
        console.error('Error updating user:', error);
        res.json(0);
    }
});

app.post('/adduser', async (req, res) => {
    const _SESSION = req.session;
    if (!_SESSION.userId) {
        console.log('Unauthorized access attempt');
        return res.json({ error: 'Unauthorized access' });
    }

    const { fname, lname, email, mobile, new_pass } = req.body;
    try {
        // Retrieves existing users
        let users = [];
        try {
            const data = await fs.readFile('./user_data/users.json', 'utf8');
            users = JSON.parse(data);
        } catch (error) {
            if (error.code !== 'ENOENT') throw error;
        }

        // Generates unique slno
        const
            maxSlno = users.length > 0 ? Math.max(...users.map(user => user.slno)) : 0,
            newSlno = maxSlno + 1;

        // Hashed password
        const hash = await bcrypt.hash(new_pass, SALT);

        // Creates new user
        const newUser = {
            slno: parseInt(newSlno),
            creation: new Date().toISOString(),
            fname,
            lname,
            email,
            mobile,
            hash,
            status: 'pending'
        };

        // Appends and writes back to file
        users.push(newUser);
        await fs.writeFile('./user_data/users.json', JSON.stringify(users, null, 2));
        await logEvent({ user_id: _SESSION.userId, event: `user ${email} added`, status: 'success' });
        res.json(1)
    } catch (error) {
        console.error('Error adding user:', error);
        await logEvent({ user_id: _SESSION.userId, event: `user ${email} added`, status: 'failure' });
        res.json(0);
    }
});

app.get('/getusers', async (req, res) => {
    const _SESSION = req.session;
    if (!_SESSION.userId) {
        console.log('Unauthorized access attempt');
        return res.json({ error: 'Unauthorized access' });
    }

    try {
        const data = await fs.readFile('./user_data/users.json', 'utf8');
        const users = JSON.parse(data);

        // Sort by slno in descending order
        users.sort((a, b) => b.slno - a.slno);
        res.json(users);
    } catch (error) {
        console.error('Error retrieving users:', error);
        res.json({ error: 'Error retrieving users' });
    }
});

app.get('/getpendingusers', async (req, res) => {
    const _SESSION = req.session;
    if (!_SESSION.userId) {
        console.log('Unauthorized access attempt');
        return res.json({ error: 'Unauthorized access' });
    }

    try {
        const
            data = await fs.readFile('./user_data/users.json', 'utf8'),
            users = JSON.parse(data);

        // Filters users where status is pending
        const pendingUsers = users.filter(user => user.status === 'pending');

        // Sort by slno in descending order
        pendingUsers.sort((a, b) => b.slno - a.slno);

        res.json(pendingUsers);
    } catch (error) {
        console.error('Error retrieving users:', error);
        res.json({ error: 'Error retrieving users' });
    }
});

app.post('/updateuser', async (req, res) => {
    const _SESSION = req.session;
    if (!_SESSION.userId) {
        console.log('Unauthorized access attempt');
        return res.json({ error: 'Unauthorized access' });
    }

    const { slno, fname, lname, email, mobile, new_pass, status } = req.body;
    try {
        // Retrieves existing users
        let users = [];
        try {
            const data = await fs.readFile('./user_data/users.json', 'utf8');
            users = JSON.parse(data);
        } catch (error) {
            if (error.code !== 'ENOENT') throw error;
        }

        // Finds user by slno
        const userIndex = users.findIndex(user => user.slno === parseInt(slno));
        if (userIndex === -1) {
            console.log('User not found', slno);
            return res.json(0);
        }

        // Checks email uniqueness
        if (email && email !== users[userIndex].email) {
            const emailExists = users.some((user, index) => index !== userIndex && user.email === email);
            if (emailExists) {
                console.log('Email already in use', email);
                return res.json(0);
            }
        }

        // Updates user data
        const updatedUser = {
            slno: parseInt(slno),
            creation: users[userIndex].creation,
            fname: fname || users[userIndex].fname,
            lname: lname || users[userIndex].lname,
            email: email || users[userIndex].email,
            mobile: mobile || users[userIndex].mobile,
            hash: new_pass && new_pass.trim() ? await bcrypt.hash(new_pass, SALT) : users[userIndex].hash,
            status: status || users[userIndex].status
        };

        // Writes back to file
        users[userIndex] = updatedUser;
        await fs.writeFile('./user_data/users.json', JSON.stringify(users, null, 2));
        await logEvent({ user_id: _SESSION.userId, event: `details updated for ${email || users[userIndex].email}`, status: 'success' });
        console.log('Updated user');
        res.json(1);
    } catch (error) {
        console.error('Error updating user:', error);
        await logEvent({ user_id: _SESSION.userId, event: `details updated for ${email}`, status: 'failure' });
        res.json(0);
    }
});

app.get('/removeuser', async (req, res) => {
    const _SESSION = req.session;
    if (!_SESSION.userId) {
        console.log('Unauthorized access attempt');
        return res.json({ error: 'Unauthorized access' });
    }

    const { slno } = req.query;
    let removed_mail;
    try {
        // Retrieves existing users
        let users = [];
        try {
            const data = await fs.readFile('./user_data/users.json', 'utf8');
            users = JSON.parse(data);
        } catch (error) {
            if (error.code !== 'ENOENT') throw error;
        }

        // Finds user by slno
        const userIndex = users.findIndex(user => user.slno === parseInt(slno));
        if (userIndex === -1) {
            console.log('User not found', slno);
            return res.json(0);
        }

        // Removes user
        removed_mail = users[userIndex].email;
        users.splice(userIndex, 1);

        // Writes back to file
        await fs.writeFile('./user_data/users.json', JSON.stringify(users, null, 2));
        await logEvent({ user_id: _SESSION.userId, event: `user ${removed_mail} removed`, status: 'success' });
        res.json(1);
    } catch (error) {
        await logEvent({ user_id: _SESSION.userId, event: `user ${removed_mail} removed`, status: 'failure' });
        console.error('Error removing user:', error);
        res.json(0);
    }
});

app.get('/getlogs', async (req, res) => {
    const _SESSION = req.session;
    if (!_SESSION.userId) {
        console.log('Unauthorized access attempt');
        return res.json({ error: 'Unauthorized access' });
    }

    try {
        const
            data = await fs.readFile('./user_data/logs.json', 'utf8'),
            logs = JSON.parse(data);

        // Filters logs by user_id and sorts by timestamp desc
        const userLogs = logs
            .filter(log => log.user_id === _SESSION.userId)
            .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

        res.json(userLogs);
    } catch (error) {
        console.error('Error retrieving logs', error.message);
        res.json({ error: 'Error retrieving logs' });
    }
});

// OTP Generation and Verification using my own developed unofficial custom dedicated WhatsApp API
// The API-KEY for sms.w3workers.com will be disposed soon, do not use it for production. It's for my personal testing purposes only!
app.post('/sendcode', async (req, res) => {
    try {
        const
            { email } = req.body,
            data = await fs.readFile('./user_data/users.json', 'utf8'),
            users = JSON.parse(data),

            // Finds user by email
            user = users.find(user => user.email === email)

        // If user exists and has a mobile number, then sends OTP (WhatsApp only)
        if (user.email) {
            let data = JSON.stringify({
                "phone": `+91${user.mobile}`,
                "host": req.hostname
            });

            let config = {
                method: 'post',
                maxBodyLength: Infinity,
                url: 'https://sms.w3workers.com/generateotp',
                headers: {
                    'Content-Type': 'application/json',
                    'x-api-key': 'CNsi3TKdQb6HNJShSOeSLifqeDlx'
                },
                data: data
            };
            console.log(data)

            axios.request(config).then((response) => {
                res.json(response.data)
                console.log('response', response.data)
            }).catch((error) => {
                res.json(error.response.data);
                console.log('error', error.response.data)
            });
        }
        else {
            res.json(0)
        }
    } catch (error) {
        res.json(0)
        console.log('forgot_pass phone not found');
    }
})

app.post('/verifycode', (req, res) => {
    const
        { ssid, vcode } = req.body,
        mobile = ssid.split(':')[0];

    let data = JSON.stringify({
        "phone": mobile,
        "otp": vcode,
        "sessionId": ssid
    });

    let config = {
        method: 'post',
        maxBodyLength: Infinity,
        url: 'https://sms.w3workers.com/verifyotp',
        headers: {
            'Content-Type': 'application/json',
            'x-api-key': 'CNsi3TKdQb6HNJShSOeSLifqeDlx'
        },
        data: data
    };

    axios.request(config).then((response) => {
        if (response.data.success == true) {
            res.json(mobile)
        }
        else {
            res.json(0)
        }
    }).catch((error) => {
        res.json(0)
    });
})

app.post('/createpassword', async (req, res) => {
    const { mobile, new_pass } = req.body;
    try {
        // Retrieves existing users
        let users = [];
        try {
            const data = await fs.readFile('./user_data/users.json', 'utf8');
            users = JSON.parse(data);
        } catch (error) {
            if (error.code !== 'ENOENT') throw error;
        }

        // Finds user by mobile number
        const userIndex = users.findIndex(user => user.mobile === mobile.replace(/^\+91/, ''));
        if (userIndex === -1) {
            console.log('User not found', mobile);
            return res.json(0);
        }
        // Updates user data
        const updateHash = {
            slno: users[userIndex].slno,
            creation: users[userIndex].creation,
            fname: users[userIndex].fname,
            lname: users[userIndex].lname,
            email: users[userIndex].email,
            mobile: users[userIndex].mobile,
            hash: new_pass && new_pass.trim() ? await bcrypt.hash(new_pass, SALT) : users[userIndex].hash,
            status: users[userIndex].status
        };

        // Writes back to file
        users[userIndex] = updateHash;
        await fs.writeFile('./user_data/users.json', JSON.stringify(users, null, 2));
        console.log('forgot password reset complete');
        res.json(1);
    } catch (error) {
        console.error('Error updating user:', error);
        res.json(0);
    }
})

// 404 Error handler
app.use((req, res) => {
    res.status(404).render("404", { title: `404 Not Found - Admin Panel v${app_version}`, page: '404' });
});

// Start Server
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));