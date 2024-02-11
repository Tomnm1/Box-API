//Version 0.5.1
const fs = require("fs");
const os = require("os");

const express = require("express");
const webcam = require("node-webcam");
const path = require("path");
const http = require("http");
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { execSync } = require('child_process');
const Gpio = require('pigpio').Gpio;

const app = express();

const jwt_secret = 'here-put-your-key';
const bcryptSaltRounds = 10;

const db = new sqlite3.Database('database.db');
const OPEN = 1500;
const CLOSE = 500;

// Utwórz tabele, jeśli nie istnieja
db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    firstName TEXT,
    lastName TEXT,
    username TEXT UNIQUE,
    password TEXT,
    photoPath TEXT
  )
`);
db.run(`
  CREATE TABLE IF NOT EXISTS boxes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE
  )
`);
db.run(`
  CREATE TABLE IF NOT EXISTS user_box_access (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId INTEGER,
    boxId INTEGER,
    FOREIGN KEY (userId) REFERENCES users (id),
    FOREIGN KEY (boxId) REFERENCES boxes (id)
  )
`);




// Utworz obiekty serw i ustaw je w polozeniu poczatkowym
const servo = [new Gpio(18, { mode: Gpio.OUTPUT }),
                                new Gpio(23, { mode: Gpio.OUTPUT }),
                                new Gpio(25, { mode: Gpio.OUTPUT })]

servo[0].servoWrite(CLOSE);
servo[1].servoWrite(CLOSE);
servo[2].servoWrite(CLOSE);

app.use(bodyParser.json());


const camera = webcam.create({
        width: 1920,
        height: 1080,
        quality: 100,
        saveShots: true,
        output: "jpeg",
        device: false,
        callbackReturn: "location",
});

const jwtMiddleware = (req, res, next) => {
        let tokenString;
        const cookies = req.headers.cookie;
        if(cookies){
                tokenString = cookies.split(';').find(str => str.startsWith('token='));
                if(!tokenString) tokenString = cookies.split(';').find(str => str.startsWith(' token='));
        }
        if(!tokenString){ return res.status(500).json('No token found');}
        const token = tokenString.split('=')[1];

        if (!token) {
                return res.status(401).json('Unauthorized');
        }

        jwt.verify(token, jwt_secret, (err, decoded) => {
                if (err) {
                        return res.status(401).json('Unauthorized');
                }

                req.user = decoded;
                next();
        });
};

app.post('/register/data', async (req, res) => {
        const { firstName, lastName, username, password } = req.body;
        const photoPath = path.join(__dirname, 'uploads', username);

        if (!fs.existsSync(photoPath)) {
                fs.mkdirSync(photoPath);
        }
        try {
                const validated = validateDate(username, password);

                if(!validated) return res.status(400).json("Credentials not validated");

                // Sprawdź, czy użytkownik o podanym username już istnieje
                const existingUser = await getUserByUsername(username);
                if (existingUser) {
                        return res.status(409).json('User already exists');
                }

                // Haszuj hasło za pomocą bcrypt
                const hashedPassword = await bcrypt.hash(password, bcryptSaltRounds);

                // Zapisz dane do bazy danych
                const userId = await insertUser(firstName, lastName, username, hashedPassword, photoPath);

                // Generuj token JWT
                const token = jwt.sign({ userId, username }, jwt_secret, {});

                // Ustaw token w pliku cookie
                res.cookie('token', token, { sameSite: 'none', secure: true });
                console.log(token);
                // Odpowiedz z ID użytkownika
                res.status(201).json({ id: userId });
        } catch (error) {
                console.error(error);
                res.status(500).json('Internal Server Error');
        }
});

app.post('/register/photo', jwtMiddleware, bodyParser.raw({type: ["image/jpeg", "image/jpg"], limit:"5mb"}), (req, res) => {
        const { role, userId } = req.user;
        getUserById(userId, (error, photoPath) =>{
                if(error) console.log(error);
                else{
                        if(photoPath){
                                console.log(photoPath);
                                try{
                                        fs.writeFile(path.join(photoPath,"image.jpg"), req.body, (e) => {
                                                if(e) throw e;
                                        });
                                        res.sendStatus(200);
                                }catch (e){
                                        res.status(500).json(e);
                                }
                        }
                        else return res.status(500).json('Internal Server Error');
                }
        });
});

app.post('/login', async (req, res) => {
        console.log("login");
        const { username, password } = req.body;
        console.log(username, password)

        try {
                if (username.toLowerCase() === 'admin' && password.toLowerCase() === 'admin') {
                        // Specjalny przypadek dla administratora
                        const token = jwt.sign({ username: 'admin', role: 'admin' }, jwt_secret, {});
                        console.log(token);
                        res.cookie('token', token, { sameSite: 'none', secure: true });
                        return res.status(200).json({ role: 'admin' });
                }

                const validated = validateDate(username, password);
                if(!validated) return res.status(400).json("Credentials not validated");

                const user = await getUserByUsername(username);
                if (!user) {
                        return res.status(401).json('Invalid username or password');
                }

                // Porównaj hasło za pomocą bcrypt
                const passwordMatch = await bcrypt.compare(password, user.password);

                if (!passwordMatch) {
                        return res.status(401).json('Invalid username or password');
                }

                // Generuj token JWT
                const token = jwt.sign({ userId: user.id, username: user.username, role: 'user' }, jwt_secret, {});

                // Ustaw token w pliku cookie
                res.cookie('token', token, { sameSite: 'none', secure: true });

                // Odpowiedz z ID użytkownika
                res.status(200).json({ userId: user.id, role: 'user' });
        } catch (error) {
                console.error(error);
                res.status(500).json('Internal Server Error');
        }
});


app.post('/logout', (req, res) => {
        // Usuń token z pliku cookie
        res.clearCookie('token');
        res.status(200).json('Logged out successfully');
});

// Zamysł tego endpointu jest taki, ze za kazdym razem jak user uruchamia aplikacje to
// idzie ten request, ktory zwraca skrzynki do ktorych ma dostep.
app.get('/data',jwtMiddleware, (req, res) => {
        console.log("data");
        const {role, userId } = req.user;
        console.log(role, userId);
        if(role !== 'user') return res.status(401).json('Forbidden');
        const query = `
                SELECT boxes.id, boxes.name
                FROM boxes
                INNER JOIN user_box_access ON boxes.id = user_box_access.boxId
                WHERE  user_box_access.userId = ?
        `;
        db.all(query, [userId], (err, rows) =>{
                if(err){
                        console.log(err);
                        res.status(500).json('Internal Server Error');
                }else{
                        res.status(200).json(rows);
                }
        });
});


// Endpoint otwierajacy skrznke
app.post('/open', jwtMiddleware, (req, res) => {
        console.log("open");
        const { role, userId } = req.user;
        const { boxId } = req.body;
        //console.log(role, userId, boxId);
        if(role !== 'user') return res.status(401).json('Forbidden');

        //kontrola czy user ma dostep do skrzynki ktora chce otworzyc, na wypadek dostepu spoza aplikacji
        const query = `
                SELECT boxes.id, boxes.name
                FROM boxes
                INNER JOIN user_box_access ON boxes.id = user_box_access.boxId
                WHERE  user_box_access.userId = ? AND boxes.id = ?
        `;
        //odpalanie query
        db.get(query, [userId, boxId], (error, row) => {
                if(error){
                        console.log(err);
                        return res.status(500).send('Internal Server Error');
                }
                //jezeli znaleziono dopasowanie, a bedzie zawsze tylko 1 to rob otwieranie
                if(row){
                        //pobranie sciezki do zdjecia z bazy + obsługa bledow
                        getUserById(userId, async (error, photoPath) =>{
                                if(error) console.log(error);
                                if(photoPath){
                                        let takenPhoto;
                                        try{
                                                const imagePath = await takePicture();
                                                takenPhoto = path.join(__dirname, imagePath);
                                        }catch(e){
                                                console.log(e);
                                                return res.status(500).send('Internal Server Error');
                                        }
                                        console.log(path.join(photoPath, "image.jpg"));
                                        console.log(takenPhoto);
                                        const accessGranted = compareFaces(path.join(photoPath, "image.jpg"), takenPhoto);

                                        if(accessGranted){
                                                try{
                                                        console.log(boxId);
                                                        openBox(boxId);
                                                }catch(e){
                                                        return res.status(500).send('Internal Server Error');
                                                }finally{
                                                        return res.status(200).json('Operation successfully');
                                                }
                                        }
                                        else{
                                                console.log("Faces do not match");
                                                return res.status(403).json("Faces do not match");
                                        }

                                }
                                else return res.status(500).json('Internal Server Error');

                        });
                }
                //klient zmanipulował w jakis sposob requesta albo admin wywalil go w miedzyczasie z dostepu
                else{
                        return res.status(401).json('Forbidden');
                }
        });
});


app.get('/admin/getusers', jwtMiddleware, async (req, res) => {
        console.log("/admin/getusers");
        const { role } = req.user;

        try {
                // Sprawdź, czy żądający użytkownik to admin
                if (role !== 'admin') return res.status(401).json('Forbidden');

                // Pobierz listę użytkowników z bazy danych
                const users = await getAllUsers();

                res.status(200).json(users);
        } catch (error) {
                console.error(error);
                res.status(500).json('Internal Server Error');
        }
});

app.get('/admin/getuserinfo', jwtMiddleware, async (req, res) => {
        console.log("/admin/getuserinfo");
        const { role } = req.user;
        const { requestedUserId } = req.body;
        try {
                // Sprawdź, czy żądający użytkownik to admin
                if (role !== 'admin') return res.status(401).json('Forbidden');
                const hasAccessBoxes = await getHasAccessBoxes(requestedUserId);
                const allBoxes = await getAllBoxes();

                const responseObject = {
                        requestedUserId,
                        hasAccessBoxes,
                        allBoxes,
                };
                res.status(200).json(responseObject);
        } catch (error) {
                console.error(error);
                res.status(500).json('Internal Server Error');
        }
});

app.post('/admin/userinfo', jwtMiddleware, (req, res) => {
        console.log("/admin/getuserinfo");
        const { role } = req.user;
        const { requestedUserId, hasAccessBoxes, newAccessRequest  } = req.body;
        console.log(requestedUserId, hasAccessBoxes, newAccessRequest);
        try {
                // Sprawdź, czy żądający użytkownik to admin
                if (role !== 'admin') return res.status(401).json('Forbidden');

                // Sprawdź, czy użytkownik ma dostęp do każdego z boxów w hasAccessBoxes
                const query1 = `
                        SELECT boxId FROM user_box_access
                        WHERE userId = ? AND boxId IN (${hasAccessBoxes.join(',')})
                  `;
                db.all(query1, [requestedUserId], (err, currentAccessRows) => {
                        console.log(currentAccessRows);
                        if (err) {
                                console.error(err);
                                return res.status(500).json('Internal Server Error');
                        }

                        // Usuń dostęp do boxów, których nie ma w newAccessRequest
                        const boxesToRemove = currentAccessRows.filter(row => !newAccessRequest.includes(row.boxId));
                        if (boxesToRemove.length > 0) {
                                const query2 = `
                        DELETE FROM user_box_access
                        WHERE userId = ? AND boxId IN (${boxesToRemove.map(box => box.boxId).join(',')})
                  `;
                                db.run(query2, [requestedUserId], (err, asd) => {
                                        console.log(asd);
                                        if (err) {
                                                console.error(err);
                                                return res.status(500).json('Internal Server Error');
                                        }
                                });
                        }

                        // Dodaj dostęp do nowych boxów
                        const boxesToAdd = newAccessRequest.filter(boxId => !currentAccessRows.some(row => row.boxId === boxId));
                        if (boxesToAdd.length > 0) {
                                const query3 = `
                        INSERT INTO user_box_access (userId, boxId)
                        VALUES ${boxesToAdd.map(boxId => `(${requestedUserId}, ${boxId})`).join(',')}
                  `;
                                db.run(query3, (err, asd) => {
                                        console.log(asd)
                                        if (err) {
                                                console.error(err);
                                                return res.status(500).json('Internal Server Error');
                                        }
                                });
                        }

                        res.status(200).json('User info updated successfully');
                });
        } catch (error) {
                console.error(error);
                res.status(500).json('Internal Server Error');
        }
});


//Obsłuż sygnały
// Ctrl+C, aby zamknąć serwomechanizm przed zakończeniem programu
process.on('SIGINT', () => {
        servo[0].servoWrite(CLOSE);
        servo[1].servoWrite(CLOSE);
        servo[2].servoWrite(CLOSE);
        process.exit();
});

// funkcja pomocnicza walidująca dane wejściowe

const validateDate = (login, password) => {
        // minumum 3 znaki, maksimum 16, akceptuje duże, małe litery oraz liczby.
        const regexLogin = /^[a-zA-Z0-9]{3,16}$/;

        //minimum 8 znaków, maksimum 16, minumum 1 duża litera, minimum 1 mała litera, minimum jeden znak specjalny
        const regexPassword = /^(?=.*\d)(?=.*[!@#$%^&*])(?=.*[a-z])(?=.*[A-Z]).{8,16}$/;

        return regexLogin.test(login) && regexPassword.test(password);

}
// funkcja pomocnicza dla endpointu /admin/getuserinfo wyciagajaca dane z bazy
async function getHasAccessBoxes(userId) {
        const query = `
    SELECT boxes.id, boxes.name
    FROM boxes
    INNER JOIN user_box_access ON boxes.id = user_box_access.boxId
    WHERE  user_box_access.userId = ?
  `;

        return new Promise((resolve, reject) => {
                db.all(query, [userId], (err, rows) => {
                        if (err) reject(err);
                        else {
                                let result = [];
                                rows.map(row => {
                                        result.push(row.id);
                                });
                                resolve(result);}
                });
        });
}

// funkcja pomocnicza dla endpointu /admin/getuserinfo wyciagajaca dane z bazy
async function getAllBoxes() {
        const query = 'SELECT * FROM boxes';

        return new Promise((resolve, reject) => {
                db.all(query, (err, rows) => {
                        if (err) reject(err);
                        else resolve(rows);
                });
        });
}


// Funkcja pomocnicza obslugujaca operacje skrzynkowe
const openBox = (boxId) =>{
        console.log(servo[boxId-1])
        console.log("BOX OPENED.")
        servo[boxId-1].servoWrite(OPEN);
        setTimeout(() => {
                servo[boxId-1].servoWrite(CLOSE);
        }, 45000);
}

// Funckja pomocnicza realizujaca zabezpieczenie biometryczne
const compareFaces = (pictureA, pictureB) =>{
        try{
                const cmd = `python3 compare_faces.py ${pictureA} ${pictureB}`;
                const result = execSync(cmd);
                console.log(result)
                return true;
        }catch(e){
                console.log(e.toString());
                return false;
        }
}

// Funkcja pomocnicza do pobierania wszystkich użytkowników z bazy danych
async function getAllUsers() {
        return new Promise((resolve, reject) => {
                const selectAllUsers = db.prepare('SELECT id, firstName, lastName FROM users');
                selectAllUsers.all((err, rows) => {
                        if (err) return reject(err);
                        resolve(rows);
                });
                selectAllUsers.finalize();
        });
}


// Funkcja pomocnicza do wykonywania zdjec
const takePicture = async () => {
        return new Promise((res, rej) => {
                const timestamp = Date.now();
                const imagePath = `./images/img_${timestamp}.jpeg`;
                camera.capture(imagePath, (err, data) => {
                        if(err){
                                rej(err);
                        }
                        else{
                                res(imagePath);
                        }
                });
        });
};

// Funkcja pomocnicza do pobierania użytkownika po nazwie użytkownika
async function getUserByUsername(username) {
        return new Promise((resolve, reject) => {
                const selectUser = db.prepare('SELECT * FROM users WHERE username = ?');
                selectUser.get([username], (err, row) => {
                        if (err) return reject(err);
                        resolve(row);
                });
                selectUser.finalize();
        });
}

// Funkcja pomocnicza do pobierania użytkownika po id
const getUserById = (id, callback) =>{
        const query = 'SELECT photoPath FROM users WHERE id = ?';
        db.get(query, [id], (err, row) => {
                if (err) {
                        console.error(err);
                        callback(err, null);
                } else {
                        callback(null, row ? row.photoPath : null);
                }
        });
}

// Funkcja pomocnicza do dodawania użytkownika do bazy danych
async function insertUser(firstName, lastName, username, password, photoPath) {
        return new Promise((resolve, reject) => {
                const insertUser = db.prepare('INSERT INTO users (firstName, lastName, username, password, photoPath) VALUES (?, ?, ?, ?, ?)');
                insertUser.run([firstName, lastName, username, password, photoPath], function (err) {
                        if (err) return reject(err);
                        resolve(this.lastID);
                });
                insertUser.finalize();
        });
}


const server = http.createServer(app);
server.listen(80, '0.0.0.0', () => console.log("Server is up!"));
