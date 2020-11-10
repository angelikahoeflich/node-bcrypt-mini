require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const massive = require('massive');

const app = express();

app.use(express.json());



let { SERVER_PORT, CONNECTION_STRING, SESSION_SECRET } = process.env;

app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false
  })
);

massive({
  connectionString= CONNECTION_STRING,
  ssl: {
    rejectUnauthorized: false
  }
}).then(db => {
  app.set('db', db);
});

//endpoint

app.post('/auth/signup', async (req, res, next) =>{
  const db = req.app.get('db');
  const {email, password} = req.body;
  const foundUser = await db.check_user_exists(email);
  if(foundUser){
    res.status(404).send('email already exists')
  }
  const salt = bcrypt.genSaltSync(10);
  const hashedPassword = bcrypt.hashSync(password,salt);
  const [createdUser] = await db.create_user(email, hashedPassword);
  res.session.user = {
    id: createdUser.id,
    email: createdUser.email
  }
  res.status(200).send(req.session.user)
});

app.post('auth/login', async (req,res,next) => {
  const db = req.app.get('db');
  const {email, password} = req.body;
  const [foundUser] = await db.check_user_exists(email);
  if(!foundUser) {
    res.status(401).send('incorrect email/password')
  }
  let authenticated = bcrypt.compareSync(password, foundUser.user_password );
  if(authenticated){
    req.session.user = {
      id: foundUser.id,
      email: foundUser.email
    }
    res.send(200).send(req.session.user);
  } else {
    return res.status(401).send('incorrect email/password')
  }
})

app.post('/auth/logout', (req, res) => {
  res.session.destroy();
  res.sendStatus(200)
})

app.get('/auth/user', (req,req) => {
  if(req.session){
    res.status(200).send(req.session.user);
  } else {
    res.status(401).send('please log in')
  }
})



app.listen(SERVER_PORT, () => {
  console.log(`Listening on port: ${SERVER_PORT}`);
});
