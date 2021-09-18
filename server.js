require('dotenv').config()
const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();

app.listen(3000);
app.use(express.json());

app.get('/', (req, res)=>{
    res.sendStatus(200)
});

let user = []

app.post('/register', (req, res)=>{

    try {
        const NewUser = {
            username: req.body.username,
            email: req.body.email,
            password: req.body.password
        }
        user.push(NewUser)
        res.status(201).send('New User ' + req.body.username+' created successfully')
    } catch (error) {
        res.sendStatus(error)
    }

})

app.post('/login', (req, res)=>{
    try {

        user.forEach(element =>{
            if (element.username === req.body.username){
                if(element.password === req.body.password){
                    const accessToken = jwt.sign(req.body.username, process.env.accessSecret)
                    res.json({
                        loginStatus: 'Login Successful', 
                        Token: accessToken
                    })
                } else {
                    res.send('Password Incorrect')
                }
            } else {
                res.send('User Not Found')
            }
        })
    } catch (error) {
        res.send(error)
    }
})

function authenticateToken(req, res, next){
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]
    if (token == null) return res.sendStatus(401)

    jwt.verify(token, process.env.accessSecret, (err, user) =>{
        if (err) return res.send(false)
        req.user = user
        next()
    })
}

app.get('/verify', authenticateToken, (req, res) =>{
    res.send(true)
})


