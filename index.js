const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require("bcryptjs");

const PORT = 3000;
const app = express();

app.use(bodyParser.json());

let users = [];

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
    users.forEach((user) =>
    {
        if (user.username === req.body.username)
        {
            res.status(400);
            res.send({"success": false, "msg": "username taken"});
        }
    });

    bcrypt.genSalt(10, (err, salt) => {
        bcrypt.hash(req.body.password, salt, (err, hash) => {
          if(err) throw err;
          const newUser =
          {
              id: users.length + 1,
              username: req.body.username,
              password: hash
          };
          users.push(newUser);
          res.send(newUser);
        });
      });

});

app.listen(PORT, () =>
{
    console.log("Server listening on port: " + PORT);
});