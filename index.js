const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const session = require('express-session');
const passport = require('passport');

require('dotenv').config();

const PORT = 3000;
const app = express();
app.use(bodyParser.json());
app.use(session({
    secret: "dfnlfelfe",
    resave: false,
    saveUninitialized: false,
}));
app.use(passport.initialize());
app.use(passport.session());

let users = [];
let todos = [];

app.get('/', (req, res) =>
{
    res.send("Hello");
});

app.get('/api/user/list', (req, res) =>
{
    res.send(users);
});

app.post('/api/user/register', (req, res) =>
{
    const authHeader = req.headers;
    const token = authHeader.cookie;

    if (token !== undefined)
    {
        res
        .redirect('/');
    }
    else
    {
        const username = req.body.username;
        const password = req.body.password;

        let usernameFound = false;

        users.forEach((user) =>
        {
            if (user.username === username)
            {
                usernameFound = true;
            }
        });

        if (usernameFound)
        {
            res.status(400);
            res.end();
        }
        else
        {
            bcrypt.genSalt(10, (err, salt) => {
                bcrypt.hash(password, salt, (err, hash) => {
                    if(err) throw err;
                    const newUser =
                    {
                        id: users.length + 1,
                        username: username,
                        password: hash
                    };
                    users.push(newUser);
                    res.send(newUser);
                });
            });
        }
    }
});

app.post('/api/user/login', (req, res) =>
{
    const authHeader = req.headers;
    const token = authHeader.cookie;

    if (token !== undefined)
    {
        res
        .redirect('/');
    }
    else
    {
        const username = req.body.username;
        const password = req.body.password;

        let User = {
            id: undefined,
            username: undefined,
            password: undefined
        }

        let usernameFound = false;

        users.forEach((user) =>
        {
            if (user.username === username)
            {
                usernameFound = true;
                User = user;
            }
        });

        if (usernameFound)
        {
            bcrypt.compare(password, User.password, (err, isMatch) =>
            {
                if(err) throw err;
                if(isMatch)
                {
                    const jwtPayload = {
                        id: User.id,
                        username: User.username
                    }
                    jwt.sign(
                        jwtPayload,
                        process.env.SECRET,
                        {
                            expiresIn: 120
                        },
                        (err, token) => {
                            if (err) { throw err }
                            res
                            .status(200)
                            .cookie('connect.sid', token)
                            .json({ success: true, token});
                        }
                    );            
                }
                else
                {
                    res
                    .status(401)
                    .end();
                }
            });
        }
        else
        {
            res
            .status(401)
            .end();
        }
    }
});

app.get('/api/secret', (req, res) =>
{
    const authHeader = req.headers;
    const token = authHeader.cookie;

    if (token === undefined)
    {
        res
        .status(401)
        .end();
    }
    else
    {
        res
        .status(200)
        .end();
    }

    res.end();
});

app.post('/api/todos', (req, res) =>
{
    const newTodo = req.body.todo;
    const token = req.headers.cookie.split("=")[1];

    if (!token)
    {
        res.sendStatus(401);
    }
    else
    {
        const user = jwt.verify(token, process.env.SECRET);
        const id = user.id;
        let userFound = false;

        todos.forEach((todo) =>
        {
            if (todo["id"] === id)
            {
                todo.todos.push(newTodo);
                userFound = true;

                res.send(todo);
            }
        });

        if (userFound === false)
        {
            const newEntry =
            {
                "id": id,
                "todos" : [newTodo]
            }

            todos.push(newEntry);

            res.send(newEntry);
        }
    }
});

app.get('/api/todos/list', (req, res) =>
{
    res.send(todos);
});

app.listen(PORT, () =>
{
    console.log("Server listening on port: " + PORT);
});