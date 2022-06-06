const express = require("express")
const app = express()
const mysql = require('mysql')
const cors = require('cors');

const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const session = require('express-session');

const path = require('path')

// if (process.env.NODE_ENV === "production") {
//     app.use(express.static('build'))
//     app.get('*', (req, res) => {
//         req.sendFile(path.resolve(__dirname, '../client/build', 'index.html'))
//     })
// }

const bcrypt = require('bcrypt')
const saltRounds = 10

const jwt = require('jsonwebtoken')

app.use(express.json())

app.use(app.use(cors({credentials: true, origin: 'https://gbg-client.vercel.app'})))
//vaiaiiiiiiiiiiiiiiiiiiiiiiiiiiii saco de cors
//fasdhfuasduhfaushdfhuasdhf
app.use(cookieParser())
app.use(bodyParser.urlencoded({ extended: true }))

app.use(session({
    key: "userId",
    secret: "teste",
    resave: false,
    saveUninitialized: false,
    cookie: {
        expires: 60 * 60 * 1000
    }
}))

const db = mysql.createConnection({

    host     : process.env.HOST || 'localhost',
    user     : process.env.USER || 'root',
    password : process.env.PASSWORD || 'password',
    database : process.env.DATABASE || 'gbgbd'
})
  
app.post("/register", (req, res) => {
    const usuario = req.body.usuario
    const email = req.body.email
    const senha = req.body.senha

    const sqlInsert = "INSERT INTO autenticacao (usuario, email, senha) VALUES (?, ?, ?);";

    bcrypt.hash(senha, saltRounds, (err, hash) => {
        if (err) {
            console.log(err)
        }
        db.query(sqlInsert, [usuario, email, hash], (err, result) => {console.log(err)});

    })
});

const verifyJWT = (req, res, next) => {
    const token = req.headers["x-access-token"]

    if (!token) {
        res.send("We need a token")
    } else {
        jwt.verify(token, "jwtSecret", (err, decoded) => {
            if(err) {
                res.json({ auth: false, message: "Fail to auth" })
            } else {
                req.userId = decoded.id;
                next()
            }
        })
    }
}

app.get('/userAuth', verifyJWT , (req, res) => {
    res.send("Congrats")
})

app.get('/categorias', (req, res) => {

    const sqlSelect = "SELECT * FROM categorias;"

    db.query(sqlSelect, (err, result) => {
        if (err) {
            res.send({ err: err})
        } else {
            res.send(result)
        }
    })
})

app.get('/login', (req, res) => {
    if(req.session.user) {
        res.send({ loggedIn: true, user: req.session.user})
    } else {
        res.send({ loggedIn: false })
    }
})

app.get('/todos-jogos', (req, res) => {
    
    const sqlSelect = "SELECT * FROM jogos";

    db.query(sqlSelect, (err, result) => {
        if (err) {
            res.send({err: err})
        } else {
            res.send(result)
        }
    })

})

app.post('/login', (req, res) => {
    const email = req.body.email
    const senha = req.body.senha

    const sqlSelect = "SELECT * FROM autenticacao WHERE email = ?;";

    db.query(sqlSelect, email, (err, result) => {
        console.log(result)
        if(err) {
            res.send({err: err})
        } 

        if (result.length > 0) {
            bcrypt.compare(senha, result[0].senha, (error, response) => {
                if (response) {
                    req.session.user = result

                    const id = result[0].id
                    const token = jwt.sign({id}, "jwtsecret", {
                        expiresIn: 300
                    })
                    req.session.user = result;

                    res.json({auth: true, token: token, result: result});
                } else {
                    res.json({ auth: false, message: "Wrong email/password"})
                }
            })
        } else {
            res.json({ auth: false, message: "Email não cadastrado"})
        }
    });
})

app.listen(process.env.PORT || 3001, () => {
    console.log("Running on port 3001")
})