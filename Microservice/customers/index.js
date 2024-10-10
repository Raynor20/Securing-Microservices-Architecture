const https = require('https');
const fs = require('fs');
const express = require('express');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');

const app = express();

const sslOptions = {
    key: fs.readFileSync('C:/Users/Kim/Downloads/Microservice/Microservice/server.key'),
    cert: fs.readFileSync('C:/Users/Kim/Downloads/Microservice/Microservice/server.cert')
}

app.use(helmet());

app.use(express.json({
    limit: '20kb'
}));

let customers = [];

function generateToken(user) {
    const payload = {
        id: user.id,
        role: user.role
    };
    return jwt.sign(payload, 'yourSecretKey', { expiresIn: '1h' });
}

function authenticateToken(req, res, next) {

    try {
        const token = req.headers['authorization']?.split(' ')[1];

        if (!token) {
            return res.sendStatus(401);
        }

        jwt.verify(token, 'yourSecretKey', (err, user) => {
            if (err) {
                return res.sendStatus(403);
            }
            req.user = user;
            next();
        })

    } catch (error) {
        res.status(500).json({ message: 'Internal Server Error'});
    }
}

function authorizeRoles(...allowedRoles) {
    return (req, res, next) => {
        if (!allowedRoles.includes(req.user.role)) {
            return res.status(403).json({ message: 'Access Denied' });
        }
        next();
    }
}

let limiter = rateLimit({
    max: 5,
    windowMs: 10 * 60 * 1000,
    message: 'Too many requests.'
});

app.use('/api', limiter);

app.post('/login', (req, res) => {
    const { username, password } = req.body;

    const user = {
        id: 1,
        username: 'MASTERJAJA',
        password: 'jajaboy',
        role: 'admin'
    }

    if (username === user.username && password === user.password) {
        const token = generateToken(user);
        return res.json({ token });
    } else {
        return res.status(401).json({ message: 'Invalid username or password' });
    }
})

app.post('/customers', (req, res) => {
    try {
        const customerId = Date.now();
        const { name } = req.body;

        if (!name) {
            return res.status(400).json({ message: 'Name is required!'});
        }

        const customer = {
            customerId,
            name
        };

        customers.push(customer);
        res.status(201).json({ message: 'Successfully added customer!'});

    } catch (error) {
        res.status(500).json({ message: 'Could Not Create Customer'});
    }
})

app.get('/customers', limiter, (req, res) => {
    try {
        if (!customers) {
            return res.status(400).json({ message: 'Customers Do Not Exist'});
        }

        res.json(customers);

    } catch (error) {
        res.status(500).json({ message: 'Could Not Retrieve Customers'});
    }
})

app.get('/customers/:customerId', authenticateToken, limiter, (req, res) => {
    try {
        const customer = customers.find(p => p.customerId == req.params.customerId);

        if (!customer) {
            return res.status(404).json({ message: 'Customer not Found'});
        }

        res.send(customer);

    } catch (error) {
        res.status(500).json({ message: 'Could Not Retrieve Customer'});
    }
})

app.put('/customers/:customerId', authenticateToken, authorizeRoles('admin'), (req, res) => {
    try {
        const customer = customers.find(p => p.customerId == req.params.customerId);

        if (!customer) {
            return res.status(400).json({ message: 'Customer not Found' });
        }

        Object.assign(customer, req.body);
        res.status(200).json({ message: 'Successfully Updated Customer' });

    } catch (error) {
        res.status(500).json({ message: 'Could Not Update Customer' });
    }
})

app.delete('/customers/:customerId', authenticateToken, authorizeRoles('admin'), (req, res) => {
    try {
        customers = customers.filter(p => p.customerId != req.params.customerId);
        res.status(200).json({ message: 'Successfully Deleted Customer'});
    } catch (error) {
        res.status(500).json({ message: 'Could Not Delete Customer'});
    }
})

https.createServer(sslOptions, app).listen(3002, () => {
    console.log('Customer Service running on HTTPS port 3002');
});
