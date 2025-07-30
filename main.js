import express from 'express';
const app = express();
const port = process.env.PORT || 3000;
import * as models from "./models/index.js";
import * as bodyParser from "body-parser";
import bcrypt from 'bcryptjs';
import * as JWT from 'jsonwebtoken';

app.get('/', (req, res, next) => {
    res.json({message: "Hello, World!"});
    // Add this temporarily to your main.js
    console.log("Connected DB:", process.env.DB_NAME, process.env.DB_HOST);

    

});

app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
});

app.use(bodyParser.default.json());

//sign up
app.post('/signup', async (req, res, next) => {
    const { email, password, encryption_key, name } = req.body;
    const modelsObj = await models.default;
    try {

        const emailExists = await modelsObj.User.findOne({attributes: ['id'], where: { email } });
        if (emailExists) {
            res.status(400);
            return res.json({message: "This email already exists", "sys_message": "email_exists"});
        }
        const passwordHash = await hashStr(password);
        const result = await modelsObj.User.create({
            email, password: passwordHash, encryption_key: await hashStr(encryption_key), name
        });
        res.json({message: "Signup is successful"});
    } catch (e) {
        console.error(e);
        res.status(500);
        res.json({ message: 'Something went wrong' })
    }
    if (!email || !password || !encryption_key || !name) {
        return res.status(400).json({ message: "All fields are required." });
    }
});

//login
app.post('/login', async (req, res, next) => {
    const { email, password } = req.body;
    const modelsObj = await models.default;
    try {
        const user = await modelsObj.User.findOne({ where: { email } });
        if (!user) {
            res.status(400);
            return res.json({message: "Invalid email or password", "sys_message": "invalid_credentials"});
        }
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            res.status(400);
            return res.json({message: "Invalid email or password", "sys_message": "invalid_credentials"});
        }

        const token = await generateJWT(user);
        res.json({message: "Login successful", token});
    } catch (e) {
        console.error(e);
        res.status(500);
        res.json({message: 'Something went wrong'})
    }
});


async function hashStr(str) {
    const salt = await bcrypt.genSalt(10);
    return bcrypt.hash(str, salt);
}

function generateJWT(user) {
    return new Promise((resolve, reject) => {
       JWT.default.sign({ id: user.id }, process.env.JWT_SECRET, { algorithm: 'HS256' }, function(err, token) {
                if (err) {
                    console.error("Error signing JWT:", err);
                    return reject(err);
                }
                resolve(token);
            });
    });
}