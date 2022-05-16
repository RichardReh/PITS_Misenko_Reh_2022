const express = require('express');
const speakeasy = require('speakeasy');
const uuid = require('uuid');
const bcrypt =require('bcrypt')
const {JsonDB} = require('node-json-db')
const {Config} = require('node-json-db/dist/lib/JsonDBConfig') 
//const qrcode = require('qrcode');
const path = require('path');
const { response } = require('express');

const app = express()

app.use(express.json())
app.set('view-engine', 'ejs')
app.use(express.urlencoded({ extended: false}))

const db = new JsonDB(new Config('NutzerDatenBank', true, false, '/'))

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '\index.html'))
})


app.get('/register',(req, res)=> {
    res.render('register.ejs')
})

app.get('/login',(req, res)=> {
    res.render('login.ejs')
})

app.get('/verify',(req, res)=>{
  res.render('verify.ejs')
})

//Nutzerregistrierung und temp secret
app.post('/register', async (req, res) => {
  const id = uuid.v4()
  const name = req.body.name
  const password = await bcrypt.hash(req.body.password, 10)

  try {
    const path = `/user/${name}`
    const temp_secret = speakeasy.generateSecret().base32
    db.push(path, { id, name, password, temp_secret })
    res.json(temp_secret)
  } catch (error) {
    console.log(error)
    res.status(500).json({ message: 'Fehler beim generieren des secrets'}) 
  }
})


app.post('/login', async (req, res)=>{
    const name = req.body.name
    const password = req.body.password
    const path = `/user/${name}`
    const user = db.getData(path)
    

    bcrypt.compare(password, user.password, function(err, myresponse){
      if(err){
        throw err
      }
      
      if(myresponse){
         return res.json({success: true, message : 'password matched, hat geklappt'})
      } else {
         return res.json({success: false, message : 'passwort falsch'})
      }
    })

})

// Token verifizieren und das secret permanent machen
app.post('/verify', async (req, res) => {
const {token, name} = req.body 

  try{
    const path = `/user/${name}`
    const user = db.getData(path)
    

    const secret = user.temp_secret
    console.log(user)

    const verified = speakeasy.totp.verify({ secret, 
      encoding: 'base32',
      token, })
      

    if (verified) {
      db.push(path, {id: user.id, name: user.name, password: user.password, secret: user.temp_secret})
      res.json({verified: true})
    } else{
        res.json({ verified: false})
    }
  } catch (error) {
    console.log(error)
    res.status(500).json({ message: 'Fehler beim finden des Nutzers'}) 
  }
})

// bereits bestätigte Token validieren
app.post('/validate', (req, res) => {
  const {token, id} = req.body 

  try{
    const path = `/user/${id}`
    const user = db.getData(path)
    

    const secret = user.secret
  

    const tokenValidates = speakeasy.totp.verify({ secret, 
      encoding: 'base32',
      token,
      window: 1 })
      

    if (tokenValidates) {
        res.json({ validated: true })
    } else{
        res.json({ validated: false})
    }
  } catch (error) {
    console.log(error)
    res.status(500).json({ message: 'Fehler beim validieren'}) 
  }
})

const port = 3002

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})



