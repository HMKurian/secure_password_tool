import express from 'express';
const app = express();
const port = process.env.PORT || 3001;
import * as models from "./models/index.js";
import * as bodyParser from "body-parser";
import bcrypt from 'bcryptjs';
import * as JWT from 'jsonwebtoken';

import {expressjwt} from "express-jwt";
import crypto from "crypto";

app.get('/', (req, res, next) => {
    res.json({message: "Hello, World!"});
    // Add this temporarily to your main.js
    console.log("Connected DB:", process.env.DB_NAME, process.env.DB_HOST);

    

});

app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
});

app.use(bodyParser.default.json());

app.use(
    expressjwt({
        secret: process.env.JWT_SECRET,
        algorithms: ["HS256"],
    }).unless({ path: ["/login", "/signup", '/'] })
);

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

app.post('/passwords/save', async (req, res, next) => {
    const { url, username, password, encryption_key, label } = req.body;
    const userId = req.auth.id;
    const modelsObj = await models.default;
    const userRecord = await modelsObj.User.findOne({
        attributes: ['encryption_key'], where: { id: userId }
    });
    if (!userRecord) {
        res.status(403);
        return res.json({message: 'Unable to find the account'});
    }
    const matched = await bcrypt.compare(encryption_key, userRecord.encryption_key);
    if (!matched) {
        res.status(400);
        return res.json({message: 'Incorrect encryption key'});
    }
    if (!(username && password && url)) {
        res.status(400);
        return res.json({message: 'Missing parameters'});
    }
    const encryptedUsername = encrypt(username, encryption_key);
    const encryptedPassword = encrypt(password, encryption_key);
    const result = await modelsObj.UserPassword.create({
        ownerUserId: userId, password: encryptedPassword, username: encryptedUsername, url, label
    });
    // users_passwords id, owner_user_id, url, username, password, shared_by_user_id, created_at, updated_at
    res.status(200);
    res.json({message: 'Password is saved'});
});

app.post('/passwords/list', async (req, res, next) => {
    const userId = req.auth.id;
    const encryptionKey = req.body.encryption_key;
    const modelsObj = await models.default;
    let passwords = await modelsObj.UserPassword.findAll({
        attributes: ['id', 'url', 'username', 'password', 'label', 'weak_encryption'],
        where: { ownerUserId: userId },
        order: [['id', 'DESC']]
    });

    const userRecord = await modelsObj.User.findOne({
        attributes: ['encryption_key'], where: { id: userId }
    });
    const matched = await bcrypt.compare(encryptionKey, userRecord.encryption_key);
    if (!matched) {
        res.status(400);
        return res.json({message: 'Incorrect encryption key'});
    }
    const passwordsArr = await Promise.all(
        passwords.map(async (element) => {
            // await upgradeWeakEncryption(element, userRecord, encryptionKey);
            element.password = decrypt(element.password, encryptionKey);
            element.username = decrypt(element.username, encryptionKey);
            return element;
        })
    );
    res.status(200);
    res.json({message: 'Success', data: passwordsArr});
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


function encrypt(unenrypted_string, key) {
    const algorithm = 'aes-256-ctr';
    const iv = crypto.randomBytes(16);
    const encKey = crypto.createHash('sha256').update(String(key)).digest('base64').slice(0, 32)
    const cipher = crypto.createCipheriv(algorithm, encKey, iv);
    let crypted = cipher.update(unenrypted_string,'utf-8',"base64") + cipher.final("base64");
    return `${crypted}-${iv.toString('base64')}`;
}

function decrypt(encStr, key) {
    const algorithm = 'aes-256-ctr';
    const encArr = encStr.split('-');
    const encKey = crypto.createHash('sha256').update(String(key)).digest('base64').slice(0, 32);
    const decipher = crypto.createDecipheriv(algorithm, encKey, Buffer.from(encArr[1], 'base64'));
    let decrypted = decipher.update(encArr[0], 'base64', 'utf-8');
    decrypted += decipher.final('utf-8');
    return decrypted;
}


async function upgradeWeakEncryption(element, userRecord, encryptionKey) {
    if (element.weak_encryption) {
        const decryptedPassword = decrypt(element.password, userRecord.encryption_key);
        const decryptedUserName = decrypt(element.username, userRecord.encryption_key);
        element.password = encrypt(decryptedPassword, encryptionKey);
        element.username = encrypt(decryptedUserName, encryptionKey);
        element.weak_encryption = false;
        await element.save();
    }
}