require('dotenv').config();  
const express = require('express');
const mysql = require('mysql2');
const PDFDocument = require('pdfkit');
const { Parser } = require('json2csv');
const ExcelJS = require('exceljs');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const fileUpload = require('express-fileupload');
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');
const multer = require('multer'); 
const cron = require('node-cron');
const moment = require('moment');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const axios = require('axios');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { OAuth2Client } = require('google-auth-library');


const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
const YOUR_DOMAIN = process.env.YOUR_DOMAIN;
const app = express();
const SECRET_KEY = 'amovertele';

app.use(passport.initialize());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.use(cors());
app.use(fileUpload());
app.use(express.static(path.join(__dirname, 'client')));

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});
const upload = multer({ storage });

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const db = mysql.createConnection({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME
});

db.connect(err => {
    if (err) {
        console.error('Database connection error:', err);
        return;
    }
    console.log('Database connected');
});

// Configuración de Nodemailer
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'duant75@gmail.com',
        pass: 'vknj wvob whqs hvuv'
    }
});



const generateRandomCode = (length = 8) => {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
};  

const sendNotification = (userId, eventType, content) => {
    db.query('SELECT email FROM Users WHERE user_id = ?', [userId], (err, results) => {
        if (err || results.length === 0) {
            console.error('Error al obtener el correo del usuario:', err);
            return;
        }

        const userEmail = results[0].email;

        const mailOptions = {
            from: 'duant75@gmail.com',
            to: userEmail,
            subject: `Notificación de ${eventType}`,
            text: content
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error('Error al enviar el correo:', error);
                return;
            }

            console.log('Correo enviado:', info.response);

            const query = 'INSERT INTO Notifications (user_id, event_type, content) VALUES (?, ?, ?)';
            db.query(query, [userId, eventType, content], (err, results) => {
                if (err) {
                    console.error('Error al registrar la notificación:', err);
                }
            });
        });
    });
};

const registerActivity = (userId, action, details) => {
    const query = 'INSERT INTO AuditLogs (user_id, action, details) VALUES (?, ?, ?)';
    db.query(query, [userId, action, details], (err, results) => {
        if (err) {
            console.error('Error al registrar la actividad:', err);
        }
    });
};

const verifySession = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    console.log('Token recibido:', token); 
    if (!token) {
        return res.status(401).json({ message: 'Access token is missing or invalid' });
    }
    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) {
            console.error('Error de verificación de token:', err);
            return res.status(401).json({ message: 'Access token is invalid or expired' });
        }
        const query = 'SELECT * FROM Sessions WHERE token = ? AND is_active = ?';
        db.query(query, [token, true], (sessionErr, sessionResults) => {
            if (sessionErr || sessionResults.length === 0) {
                console.error('Error de sesión o sesión no activa:', sessionErr);
                return res.status(401).json({ message: 'Session is not active' });
            }
            req.user = decoded;
            next();
        });
    });
};


app.post('/google-login', async (req, res) => {
    const { token } = req.body;

    try {
        const ticket = await client.verifyIdToken({
            idToken: token,
            audience: process.env.GOOGLE_CLIENT_ID,
        });

        const payload = ticket.getPayload();
        const { sub, email, given_name = 'GoogleUser', family_name = 'GoogleLastName' } = payload; // Agregar valores por defecto

        // Generar un username basado en el email
        const username = email.split('@')[0];

        db.query('SELECT * FROM Users WHERE google_id = ? OR email = ?', [sub, email], (err, results) => {
            if (err) {
                console.error('Error al buscar el usuario en la base de datos:', err);
                return res.status(500).json({ message: 'Server error' });
            }

            if (results.length === 0) {
                // Crear un nuevo usuario si no existe, con valores por defecto para first_name y last_name
                db.query(
                    'INSERT INTO Users (google_id, email, username, first_name, last_name, role) VALUES (?, ?, ?, ?, ?, "user")',
                    [sub, email, username, given_name, family_name],
                    (insertErr, insertResults) => {
                        if (insertErr) {
                            console.error('Error al crear el usuario:', insertErr);
                            return res.status(500).json({ message: 'Server error' });
                        }

                        const user = {
                            user_id: insertResults.insertId,
                            role: 'user',
                        };

                        const token = jwt.sign({ id: user.user_id, role: user.role }, SECRET_KEY, { expiresIn: '1h' });

                        res.json({ success: true, token });
                    }
                );
            } else {
                const user = results[0];
                const token = jwt.sign({ id: user.user_id, role: user.role }, SECRET_KEY, { expiresIn: '1h' });

                res.json({ success: true, token });
            }
        });
    } catch (error) {
        console.error('Error al verificar el token de Google:', error);
        res.status(400).json({ message: 'Error verifying Google token' });
    }
});


app.post('/create-checkout-session', verifySession, async (req, res) => {
    console.log('Stripe Secret Key:', process.env.STRIPE_SECRET_KEY);
    try {
        const { items, client_id, discount } = req.body; // Obtener el descuento

        // Crear la sesión de Stripe Checkout aplicando el descuento a cada artículo
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            line_items: items.map(item => ({
                price_data: {
                    currency: 'usd',
                    product_data: {
                        name: item.name,
                    },
                    // Aplicar el descuento a cada producto individual
                    unit_amount: Math.round((item.price - (item.price * discount)) * 100), // Aplicar el descuento y convertir a centavos
                },
                quantity: item.quantity,
            })),
            mode: 'payment',
            success_url: `http://localhost:3000/success?session_id={CHECKOUT_SESSION_ID}`,
            cancel_url: `http://localhost:3000/cancel`,
            automatic_tax: { enabled: true },
        });

        // Guardar la orden en la base de datos
        const formattedDate = moment().format('YYYY-MM-DD HH:mm:ss');
        const totalAmount = items.reduce((total, item) => total + (item.price * item.quantity), 0) * (1 - discount);
        const query = 'INSERT INTO Orders (client_id, total_amount, status, order_date, stripe_session_id) VALUES (?, ?, "pending", ?, ?)';
        db.query(query, [client_id, totalAmount, formattedDate, session.id], (err, orderResults) => {
            if (err) {
                console.error('Error inserting order:', err);
                return res.status(500).send('Server error during order insertion');
            }

            const orderId = orderResults.insertId;

            items.forEach(item => {
                const itemQuery = 'INSERT INTO OrderItems (order_id, product_id, quantity, unit_price) VALUES (?, ?, ?, ?)';
                db.query(itemQuery, [orderId, item.product_id, item.quantity, item.price], (err) => {
                    if (err) {
                        console.error('Error inserting order item:', err);
                        return res.status(500).send('Server error during order items insertion');
                    }
                });
            });

            // Responder con la URL de la sesión de Stripe
            res.status(200).json({ url: session.url });
        });

    } catch (error) {
        console.error('Error creating checkout session:', error);
        res.status(500).send('Server error');
    }
});


app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    db.query('SELECT * FROM Users WHERE username = ?', [username], async (err, results) => {
        if (err) return res.status(500).json({ message: 'Server error' });
        if (results.length === 0) return res.status(404).json({ message: 'User not found' });

        const user = results[0];
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) return res.status(401).json({ message: 'Invalid password' });

        const token = jwt.sign({ id: user.user_id, role: user.role }, SECRET_KEY, { expiresIn: '1h' });

        const sessionQuery = 'INSERT INTO Sessions (user_id, token, is_active) VALUES (?, ?, ?)';
        db.query(sessionQuery, [user.user_id, token, true], (sessionErr, sessionResult) => {
            if (sessionErr) {
                console.error('Error al registrar la sesión:', sessionErr);
                return res.status(500).json({ message: 'Error al registrar la sesión' });
            }

            // Lógica para mostrar el sidebar solo al admin
            const showSidebar = user.role === 'admin';

            registerActivity(user.user_id, 'Inicio de sesión', `Usuario ${username} inició sesión`);

            res.status(200).json({ 
                success: true, 
                token, 
                user: { 
                    username: user.username, 
                    role: user.role,
                    showSidebar  // Devuelve el flag para mostrar el sidebar
                } 
            });
        });
    });
});


app.post('/logout', verifySession, (req, res) => {
    const token = req.headers['authorization']?.split(' ')[1];

    const query = 'UPDATE Sessions SET is_active = ? WHERE token = ?';
    db.query(query, [false, token], (err, results) => {
        if (err) {
            console.error('Error al cerrar la sesión:', err);
            return res.status(500).json({ message: 'Error al cerrar la sesión' });
        }

        registerActivity(req.user.id, 'Cierre de sesión', `Usuario ${req.user.id} cerró sesión`);

        res.status(200).json({ success: true, message: 'Sesión cerrada exitosamente' });
    });
});

app.post('/forgot-password', (req, res) => {
    const { email } = req.body;
    const tempPassword = crypto.randomBytes(4).toString('hex');  
    const token = crypto.randomBytes(20).toString('hex');

    const hashedTempPassword = bcrypt.hashSync(tempPassword, 10);

    const expires = new Date(Date.now() + 3600000).toISOString().slice(0, 19).replace('T', ' ');

    db.query('UPDATE Users SET reset_password_token = ?, reset_password_expires = ?, password = ? WHERE email = ?', 
    [token, expires, hashedTempPassword, email], (err, result) => {
        if (err || result.affectedRows === 0) {
            console.error('Error updating user with reset token:', err);
            return res.status(400).send({ message: 'Email no encontrado' });
        }

        const mailOptions = {
            from: 'tu_correo@gmail.com',
            to: email,
            subject: 'Restablecimiento de Contraseña',
            text: `Tu nueva contraseña temporal es: ${tempPassword}\n\n` +
                  `Usa esta contraseña temporal para iniciar sesión y luego cambia tu contraseña a una nueva.\n\n` +
                  `Haz clic en el siguiente enlace para completar el proceso:\n\n` +
                  `http://localhost:3000/reset-password/${token}\n\n` +
                  `Si no solicitaste esto, ignora este correo y tu contraseña permanecerá sin cambios.\n`
        };

        transporter.sendMail(mailOptions, (err, response) => {
            if (err) {
                console.error('Error sending reset email:', err);
                return res.status(500).send({ message: 'Error al enviar el correo' });
            }
            res.status(200).send({ message: 'Correo enviado con éxito con la contraseña temporal' });
        });
    });
});

app.post('/reset-password/:token', (req, res) => {
    const { token } = req.params;
    const { password } = req.body;

    db.query('SELECT * FROM Users WHERE reset_password_token = ? AND reset_password_expires > ?', 
    [token, new Date().toISOString().slice(0, 19).replace('T', ' ')], (err, results) => {
        if (err || results.length === 0) {
            return res.status(400).send({ message: 'El token es inválido o ha expirado' });
        }

        const user = results[0];
        const isPasswordSame = bcrypt.compareSync(password, user.password);

        if (isPasswordSame) {
            return res.status(400).send({ message: 'La nueva contraseña no puede ser igual a la contraseña temporal' });
        }

        const hashedPassword = bcrypt.hashSync(password, 10);
        db.query('UPDATE Users SET password = ?, reset_password_token = NULL, reset_password_expires = NULL WHERE reset_password_token = ?', 
        [hashedPassword, token], (err) => {
            if (err) {
                return res.status(500).send({ message: 'Error al restablecer la contraseña' });
            }
            res.status(200).send({ message: 'Contraseña restablecida con éxito' });
        });
    });
});

app.post('/register', async (req, res) => {
    const { username, firstName, lastName, email, birthDate, password, identificationType, identificationNumber } = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        const userQuery = 'INSERT INTO Users (username, first_name, last_name, email, birth_date, password, role) VALUES (?, ?, ?, ?, ?, ?, ?)';
        const userValues = [username, firstName, lastName, email, birthDate, hashedPassword, 'user'];

        db.query(userQuery, userValues, (err, result) => {
            if (err) {
                console.error('Error al registrar el usuario en la base de datos:', err);
                res.status(500).json({ success: false, message: 'Error al registrar el usuario' });
                return;
            }
        
            const userId = result.insertId; 

            const clientQuery = 'INSERT INTO Clients (user_id, name, address, contact_info, client_type, identification_number, email, identification_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?)';
            const clientValues = [
                userId,
                `${firstName} ${lastName}`,
                '', 
                email, 
                'individual', 
                identificationNumber,
                email,
                identificationType
            ];
            
            db.query(clientQuery, clientValues, (err, clientResult) => {
                if (err) {
                    console.error('Error al registrar el cliente en la base de datos:', err);
                    res.status(500).json({ success: false, message: 'Error al registrar el cliente' });
                    return;
                }
            
                res.status(201).json({ success: true, message: 'Usuario y cliente registrados con éxito' });
            }); 
        });
    } catch (error) {
        console.error('Error durante el proceso de registro:', error);
        res.status(500).json({ success: false, message: 'Error al registrar el usuario' });
    }
});

app.post('/reviews', verifySession, (req, res) => {
    const { product_id, review_content, rating } = req.body;
    const user_id = req.user.id;
  
    const query = 'INSERT INTO Reviews (user_id, product_id, review_content, rating) VALUES (?, ?, ?, ?)';
    db.query(query, [user_id, product_id, review_content, rating], (err, results) => {
      if (err) {
        console.error('Error al agregar reseña:', err);
        return res.status(500).json({ message: 'Error al agregar reseña' });
      }
      res.status(201).json({ success: true, message: 'Reseña agregada con éxito' });
    });
  });

  app.get('/reviews/:productId', (req, res) => {
    const { productId } = req.params;
  
    const query = 'SELECT r.*, u.username FROM Reviews r JOIN Users u ON r.user_id = u.user_id WHERE product_id = ?';
    db.query(query, [productId], (err, results) => {
      if (err) {
        console.error('Error al obtener reseñas:', err);
        return res.status(500).json({ message: 'Error al obtener reseñas' });
      }
      res.json(results);
    });
  });

  app.post('/admin/coupons', (req, res) => {
    const { discount, expiration_date, usage_limit } = req.body;
    const code = generateRandomCode(); // Generar el código aleatorio

    const query = 'INSERT INTO coupons (code, discount, expiration_date, usage_limit) VALUES (?, ?, ?, ?)';
    db.query(query, [code, discount, expiration_date, usage_limit || null], (err, result) => {
        if (err) {
            console.error('Error al crear el cupón:', err);
            return res.status(500).json({ message: 'Error al crear el cupón' });
        }
        res.status(201).json({ message: 'Cupón creado exitosamente', code });
    });
});

app.post('/admin/coupons/batch', (req, res) => {
    const { coupons } = req.body;

    // Inserción de los cupones en batch
    const query = 'INSERT INTO coupons (code, discount, expiration_date, usage_limit) VALUES ?';
    const values = coupons.map(coupon => [coupon.code, coupon.discount, coupon.expiration_date, coupon.usage_limit]);

    db.query(query, [values], (err, result) => {
        if (err) {
            console.error('Error al crear los cupones:', err);
            return res.status(500).json({ message: 'Error al crear los cupones' });
        }
        res.status(201).json({ message: 'Cupones creados exitosamente' });
    });
});


// Validar un cupón
app.post('/coupons/validate', (req, res) => {
    const { code } = req.body;

    const query = 'SELECT * FROM coupons WHERE code = ? AND is_active = TRUE AND expiration_date >= CURDATE() AND (usage_limit IS NULL OR usage_limit > 0)';
    db.query(query, [code], (err, results) => {
        if (err) {
            console.error('Error al validar el cupón:', err);
            return res.status(500).json({ message: 'Error al validar el cupón' });
        }

        if (results.length === 0) {
            return res.status(404).json({ message: 'Cupón inválido, expirado o sin uso disponible' });
        }

        res.json(results[0]);
    });
});

// Aplicar un cupón (reducir el límite de uso)
app.post('/coupons/use', (req, res) => {
    const { code } = req.body;

    const query = 'SELECT * FROM coupons WHERE code = ? AND is_active = TRUE AND expiration_date >= CURDATE() AND (usage_limit IS NULL OR usage_limit > 0)';
    db.query(query, [code], (err, results) => {
        if (err) {
            console.error('Error al validar el cupón:', err);
            return res.status(500).json({ message: 'Error al validar el cupón' });
        }

        if (results.length === 0) {
            return res.status(404).json({ message: 'Cupón inválido o sin uso disponible' });
        }

        const coupon = results[0];
        if (coupon.usage_limit !== null) {
            const updateQuery = 'UPDATE coupons SET usage_limit = usage_limit - 1 WHERE coupon_id = ?';
            db.query(updateQuery, [coupon.coupon_id], (err, updateResult) => {
                if (err) {
                    console.error('Error al actualizar el límite de uso del cupón:', err);
                    return res.status(500).json({ message: 'Error al aplicar el cupón' });
                }
                res.status(200).json({ message: 'Cupón aplicado correctamente' });
            });
        } else {
            res.status(200).json({ message: 'Cupón aplicado correctamente' });
        }
    });
});
  
// Endpoint para actualizar el perfil del usuario
app.put('/update-profile', verifySession, (req, res) => {
    const { user_id } = req.user;
    const { newUsername, newEmail, newFirstName, newLastName, newBirthDate, newProfileImage } = req.body;

    // Validación básica del correo electrónico
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (newEmail && !emailRegex.test(newEmail)) {
        return res.status(400).json({ message: 'El formato del correo electrónico no es válido' });
    }

    const query = `
        UPDATE Users 
        SET username = ?, email = ?, first_name = ?, last_name = ?, birth_date = ?, profile_image = ?
        WHERE user_id = ?
    `;

    db.query(query, [newUsername, newEmail, newFirstName, newLastName, newBirthDate, newProfileImage, user_id], (err, results) => {
        if (err) {
            console.error('Error al actualizar el perfil:', err);
            return res.status(500).json({ message: 'Error al actualizar el perfil' });
        }

        const details = `Usuario actualizó su perfil: username = ${newUsername}, email = ${newEmail}, first_name = ${newFirstName}, last_name = ${newLastName}`;
        registerActivity(user_id, 'Cambio de perfil', details);

        res.status(200).json({ success: true, message: 'Perfil actualizado exitosamente' });
    });
});



app.post('/perform-action', verifySession, (req, res) => {
    const { user_id } = req.user;
    const { actionDetails } = req.body;

    registerActivity(user_id, 'Realizó una acción', `Detalles de la acción: ${actionDetails}`);

    res.status(200).json({ success: true, message: 'Acción realizada exitosamente' });
});

app.post('/system-update', verifySession, (req, res) => {
    const { updateDetails } = req.body;

    db.query('SELECT user_id FROM Users', (err, results) => {
        if (err) {
            console.error('Error al obtener usuarios:', err);
            return res.status(500).send('Server error');
        }

        results.forEach(user => {
            sendNotification(user.user_id, 'Actualización del Sistema', updateDetails);
        });

        res.status(200).send('Notificaciones enviadas');
    });
});

app.get('/notifications', verifySession, (req, res) => {
    const query = 'SELECT * FROM Notifications';
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error al obtener notificaciones:', err);
            return res.status(500).send('Server error');
        }
        res.json(results);
    });
});


app.post('/transactions', verifySession, (req, res) => {
    const { productId, quantity } = req.body;
    db.query('INSERT INTO Transactions (product_id, quantity) VALUES (?, ?)', [productId, quantity], (err, results) => {
        if (err) {
            console.error('Error creating transaction:', err);
            return res.status(500).send('Server error');
        }
        db.query('UPDATE Products SET stock = stock - ? WHERE product_id = ?', [quantity, productId], (updateErr) => {
            if (updateErr) {
                console.error('Error updating product stock:', updateErr);
                return res.status(500).send('Server error');
            }
            checkLowStock(productId);
            res.status(201).send('Transaction created and stock updated');
        });
    });
});

app.get('/transactions', verifySession, (req, res) => {
    const query = `
        SELECT t.*, c.pending_balance 
        FROM Transactions t
        JOIN Clients c ON t.client_id = c.client_id`;
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error al ejecutar la consulta:', err);
            return res.status(500).send('Server error');
        }
        res.json(results);
    });
});

app.get('/transactions/:clientId', verifySession, (req, res) => {
    const { clientId } = req.params;
    const query = 'SELECT * FROM Transactions WHERE client_id = ?';
    db.query(query, [clientId], (err, results) => {
        if (err) {
            console.error('Error al ejecutar la consulta:', err);
            return res.status(500).send('Server error');
        }
        res.json(results);
    });
});

app.post('/transactions', verifySession, (req, res) => {
    const { client_id, order_date, item_description, quantity, unit_price } = req.body;
    const total_price = quantity * unit_price;
    const query = 'INSERT INTO Transactions (client_id, order_date, item_description, quantity, unit_price, total_price) VALUES (?, ?, ?, ?, ?, ?)';
    db.query(query, [client_id, order_date, item_description, quantity, unit_price, total_price], (err, results) => {
        if (err) {
            console.error('Error al insertar transacción:', err);
            return res.status(500).send('Server error');
        }
        res.status(201).send('Transaction created');
    });
});

app.get('/generate-general-report', verifySession, (req, res) => {
    const query = `
        SELECT t.*, c.name AS client_name, c.pending_balance 
        FROM Transactions t
        JOIN Clients c ON t.client_id = c.client_id`;
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error al ejecutar la consulta:', err);
            return res.status(500).send('Server error');
        }
        const html = `
            <h1>Informe General de Transacciones</h1>
            <table border="1">
                <tr>
                    <th>ID Transacción</th>
                    <th>ID Cliente</th>
                    <th>Nombre del Cliente</th>
                    <th>Fecha del Pedido</th>
                    <th>Descripción del Artículo</th>
                    <th>Cantidad</th>
                    <th>Precio Unitario</th>
                    <th>Precio Total</th>
                    <th>Saldo Pendiente</th>
                </tr>
                ${results.map(transaction => `
                <tr>
                    <td>${transaction.transaction_id}</td>
                    <td>${transaction.client_id}</td>
                    <td>${transaction.client_name}</td>
                    <td>${transaction.order_date}</td>
                    <td>${transaction.item_description}</td>
                    <td>${transaction.quantity}</td>
                    <td>${transaction.unit_price}</td>
                    <td>${transaction.total_price}</td>
                    <td>${transaction.pending_balance}</td>
                </tr>`).join('')}
            </table>
        `;
        pdf.create(html).toStream((err, stream) => {
            if (err) {
                return res.status(500).send('Error generating PDF');
            }
            res.setHeader('Content-Type', 'application/pdf');
            stream.pipe(res);
        });
    });
});

app.get('/clients', verifySession, (req, res) => {
    db.query('SELECT * FROM Clients', (err, results) => {
        if (err) return res.status(500).send('Server error');
        res.status(200).send(results);
    });
});

app.get('/clients/:id', verifySession, (req, res) => {
    const { id } = req.params;
    db.query('SELECT * FROM Clients WHERE client_id = ?', [id], (err, results) => {
        if (err) return res.status(500).send('Server error');
        if (results.length === 0) return res.status(404).send('Client not found');
        res.status(200).send(results[0]);
    });
});

app.post('/clients', verifySession, (req, res) => {
    const { user_id, name, address, contact_info, client_type, pending_balance, identification_number, email, identification_type } = req.body;

    db.query(
        'INSERT INTO Clients (user_id, name, address, contact_info, client_type, pending_balance, identification_number, email, identification_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)', 
        [user_id, name, address, contact_info, client_type, pending_balance, identification_number, email, identification_type], 
        (err, results) => {
            if (err) return res.status(500).send('Server error');
            res.status(201).send('Client added');
        }
    );
});

app.put('/clients/:id', verifySession, (req, res) => {
    const { id } = req.params;
    const { name, address, contact_info, client_type, pending_balance, identification_number, email, identification_type } = req.body;

    db.query(
        'UPDATE Clients SET name = ?, address = ?, contact_info = ?, client_type = ?, pending_balance = ?, identification_number = ?, email = ?, identification_type = ? WHERE client_id = ?', 
        [name, address, contact_info, client_type, pending_balance, identification_number, email, identification_type, id], 
        (err, results) => {
            if (err) return res.status(500).send('Server error');
            res.status(200).send('Client updated');
        }
    );
});

app.delete('/clients/:id', verifySession, (req, res) => {
    const { id } = req.params;

    db.query('DELETE FROM Clients WHERE client_id = ?', [id], (err, results) => {
        if (err) return res.status(500).send('Server error');
        res.status(200).send('Client deleted');
    });
});

app.get('/products', (req, res) => {
    const query = 'SELECT * FROM Products';
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching products:', err);
            return res.status(500).send('Server error');
        }
        const products = results.map(product => ({
            ...product,
            image: product.image ? `http://localhost:3001/uploads/${product.image}` : null
        }));
        res.json(products);
    });
});

app.get('/products/:id', (req, res) => {
    const { id } = req.params;
    const query = 'SELECT * FROM Products WHERE product_id = ?';
    db.query(query, [id], (err, results) => {
        if (err) {
            console.error('Error fetching product:', err);
            return res.status(500).send('Server error');
        }
        const product = results[0];
        product.image = product.image ? `http://localhost:3001/uploads/${product.image}` : null;
        res.json(product);
    });
});

app.post('/products', verifySession, (req, res) => {
    const { name, description, category, price, cost_price, stock, iva, discount } = req.body; // Añade cost_price

    let image = null;
    if (req.files && req.files.image) {
        const imageFile = req.files.image;
        image = Date.now() + path.extname(imageFile.name);
        imageFile.mv(path.join(__dirname, 'uploads', image), (err) => {
            if (err) {
                console.error('Error uploading image:', err);
                return res.status(500).send('Error uploading image');
            }
        });
    }

    const query = 'INSERT INTO Products (name, description, category, price, cost_price, stock, image, iva, discount) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'; // Incluye cost_price en la consulta
    db.query(query, [name, description, category, price, cost_price, stock, image, iva, discount], (err, results) => { // Incluye cost_price en los valores
        if (err) {
            console.error('Error adding product:', err);
            return res.status(500).send('Server error');
        }
        res.status(201).send('Product added');
    });
});


app.put('/products/:id', verifySession, (req, res) => {
    const { id } = req.params;
    const { name, description, category, price, cost_price, stock, iva, discount } = req.body; // Añade cost_price

    let query = 'UPDATE Products SET name = ?, description = ?, category = ?, price = ?, cost_price = ?, stock = ?, iva = ?, discount = ?'; // Incluye cost_price en la consulta
    const values = [name, description, category, price, cost_price, stock, iva, discount]; // Incluye cost_price en los valores

    if (req.files && req.files.image) {
        const imageFile = req.files.image;
        const image = Date.now() + path.extname(imageFile.name);
        imageFile.mv(path.join(__dirname, 'uploads', image), (err) => {
            if (err) {
                console.error('Error uploading image:', err);
                return res.status(500).send('Error uploading image');
            }
        });
        query += ', image = ?';
        values.push(image);
    }

    query += ' WHERE product_id = ?';
    values.push(id);

    db.query(query, values, (err, results) => {
        if (err) {
            console.error('Error updating product:', err);
            return res.status(500).send('Server error');
        }
        res.send('Product updated');
    });
});


app.delete('/products/:id', verifySession, (req, res) => {
    const { id } = req.params;
    const query = 'DELETE FROM Products WHERE product_id = ?';
    db.query(query, [id], (err, results) => {
        if (err) {
            console.error('Error deleting product:', err);
            return res.status(500).send('Server error');
        }
        res.send('Product deleted');
    });
});

app.post('/orders', verifySession, (req, res) => {
    const { client_id, total_amount, items } = req.body;
    const query = 'INSERT INTO orders (client_id, order_date, status, total_amount) VALUES (?, NOW(), "pending", ?)';
    db.query(query, [client_id, total_amount], (err, results) => {
        if (err) {
            console.error('Error creating order:', err);
            return res.status(500).send('Server error');
        }
        const orderId = results.insertId;
        const orderItems = items.map(item => [orderId, item.product_id, item.description, item.quantity, item.unit_price]);
        const orderItemsQuery = 'INSERT INTO orderitems (order_id, product_id, description, quantity, unit_price) VALUES ?';
        db.query(orderItemsQuery, [orderItems], (err, results) => {
            if (err) {
                console.error('Error creating order items:', err);
                return res.status(500).send('Server error');
            }
            res.status(201).send('Order created');
        });
    });
});

app.get('/admin/orders', verifySession, (req, res) => {
    const query = 'SELECT * FROM orders';
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching orders:', err);
            return res.status(500).send('Server error');
        }
        res.json(results);
    });
});



app.get('/users', verifySession, (req, res) => {
    const query = 'SELECT user_id, username, email, created_at, role FROM Users';
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error al ejecutar la consulta:', err);
            return res.status(500).send('Server error');
        }
        res.json(results);
    });
});

// Endpoint para obtener los datos de perfil de un usuario por ID
app.get('/users/:id', verifySession, (req, res) => {
    const { id } = req.params;

    console.log(`Obteniendo datos de usuario con ID: ${id}`); // Depuración

    const query = `
        SELECT user_id, username, email, created_at, role, first_name, last_name, birth_date, profile_image
        FROM Users 
        WHERE user_id = ?
    `;

    db.query(query, [id], (err, results) => {
        if (err) {
            console.error('Error al ejecutar la consulta:', err);
            return res.status(500).json({ message: 'Error en el servidor' });
        }

        if (results.length === 0) {
            console.log('Usuario no encontrado'); // Depuración
            return res.status(404).json({ message: 'Usuario no encontrado' });
        }

        console.log('Resultados de usuario:', results[0]); // Depuración
        res.status(200).json(results[0]);
    });
});



app.put('/users/:id', verifySession, (req, res) => {
    const { id } = req.params;
    const { username, email, role } = req.body;
    const query = 'UPDATE Users SET username = ?, email = ?, role = ? WHERE user_id = ?';
    db.query(query, [username, email, role, id], (err, results) => {
        if (err) {
            console.error('Error al actualizar usuario:', err);
            return res.status(500).send('Server error');
        }
        res.send('User updated');
    });
});

app.delete('/users/:id', verifySession, (req, res) => {
    const { id } = req.params;
    const query = 'DELETE FROM Users WHERE user_id = ?';
    db.query(query, [id], (err, results) => {
        if (err) {
            console.error('Error al eliminar usuario:', err);
            return res.status(500).send('Server error');
        }
        res.send('User deleted');
    });
});

app.get('/sales', verifySession, (req, res) => {
    const query = `
        SELECT 
            i.invoice_id AS sale_id, 
            i.issue_date AS sale_date, 
            i.total_amount 
        FROM 
            invoices i
        ORDER BY 
            i.issue_date DESC
    `;
    db.query(query, (err, results) => {
        if (err) return res.status(500).send('Server error');
        res.status(200).send(results);
    });
});

app.post('/sales', verifySession, (req, res) => {
    const { sale_date, total_amount, items } = req.body;

    db.query('INSERT INTO Sales (sale_date, total_amount) VALUES (?, ?)', [sale_date, total_amount], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Server error');
        }

        const sale_id = results.insertId;

        const saleItems = items.map(item => [sale_id, item.description, item.quantity, item.unit_price]);

        db.query('INSERT INTO SaleItems (sale_id, description, quantity, unit_price) VALUES ?', [saleItems], (err, results) => {
            if (err) {
                console.error(err);
                return res.status(500).send('Server error');
            }
            res.status(201).send('Sale added');
        });
    });
});


app.get('/generate-financial-report', verifySession, (req, res) => {
    const { start_date, end_date } = req.query;

    // Convertir las fechas actuales en objetos moment.js
    const startDate = moment(start_date);
    const endDate = moment(end_date);

    // Calcular las fechas del período anterior (en este caso, restando un mes)
    const previousPeriodStart = startDate.clone().subtract(1, 'month').format('YYYY-MM-DD');
    const previousPeriodEnd = endDate.clone().subtract(1, 'month').format('YYYY-MM-DD');

    console.log('Start Date:', start_date);
    console.log('End Date:', end_date);
    console.log('Previous Period Start:', previousPeriodStart);
    console.log('Previous Period End:', previousPeriodEnd);

    const revenueQuery = `
        SELECT SUM(i.total_amount) AS revenue
        FROM invoices i
        WHERE i.issue_date BETWEEN ? AND ?
    `;

    const costOfGoodsSoldQuery = `
        SELECT SUM(ii.quantity * p.cost_price) AS cost_of_goods_sold
        FROM invoiceitems ii
        JOIN products p ON ii.product_id = p.product_id
        WHERE ii.invoice_id IN (
            SELECT invoice_id FROM invoices WHERE issue_date BETWEEN ? AND ?
        )
    `;

    const operatingExpensesQuery = `
        SELECT SUM(amount) AS operating_expenses
        FROM expenses
        WHERE date BETWEEN ? AND ?
    `;

    const revenueByCategoryQuery = `
        SELECT p.category, SUM(ii.quantity * ii.unit_price) AS revenue
        FROM invoiceitems ii
        JOIN products p ON ii.product_id = p.product_id
        JOIN invoices i ON ii.invoice_id = i.invoice_id
        WHERE i.issue_date BETWEEN ? AND ?
        GROUP BY p.category
    `;

    const previousPeriodRevenueQuery = `
        SELECT SUM(i.total_amount) AS revenue
        FROM invoices i
        WHERE i.issue_date BETWEEN ? AND ?
    `;

    const previousPeriodCostOfGoodsSoldQuery = `
        SELECT SUM(ii.quantity * p.cost_price) AS cost_of_goods_sold
        FROM invoiceitems ii
        JOIN products p ON ii.product_id = p.product_id
        WHERE ii.invoice_id IN (
            SELECT invoice_id FROM invoices WHERE issue_date BETWEEN ? AND ?
        )
    `;

    const previousPeriodExpensesQuery = `
        SELECT SUM(amount) AS operating_expenses
        FROM expenses
        WHERE date BETWEEN ? AND ?
    `;

    const expensesByCategoryQuery = `
        SELECT category, SUM(amount) AS total_expense
        FROM expenses
        WHERE date BETWEEN ? AND ?
        GROUP BY category
    `;

    db.query(revenueQuery, [start_date, end_date], (err, revenueResults) => {
        if (err) return res.status(500).send('Error fetching revenue');

        db.query(costOfGoodsSoldQuery, [start_date, end_date], (err, cogsResults) => {
            if (err) return res.status(500).send('Error fetching cost of goods sold');

            db.query(operatingExpensesQuery, [start_date, end_date], (err, expensesResults) => {
                if (err) return res.status(500).send('Error fetching operating expenses');

                db.query(revenueByCategoryQuery, [start_date, end_date], (err, revenueByCategoryResults) => {
                    if (err) return res.status(500).send('Error fetching revenue by category');

                    db.query(expensesByCategoryQuery, [start_date, end_date], (err, expensesByCategoryResults) => {
                        if (err) return res.status(500).send('Error fetching expenses by category');

                        db.query(previousPeriodRevenueQuery, [previousPeriodStart, previousPeriodEnd], (err, previousRevenueResults) => {
                            if (err) return res.status(500).send('Error fetching previous revenue');

                            db.query(previousPeriodCostOfGoodsSoldQuery, [previousPeriodStart, previousPeriodEnd], (err, previousCogsResults) => {
                                if (err) return res.status(500).send('Error fetching previous cost of goods sold');

                                db.query(previousPeriodExpensesQuery, [previousPeriodStart, previousPeriodEnd], (err, previousExpensesResults) => {
                                    if (err) return res.status(500).send('Error fetching previous expenses');

                                    const revenue = revenueResults[0].revenue || 0;
                                    const costOfGoodsSold = cogsResults[0].cost_of_goods_sold || 0;
                                    const operatingExpenses = expensesResults[0].operating_expenses || 0;
                                    const grossProfit = revenue - costOfGoodsSold;
                                    const netIncome = grossProfit - operatingExpenses;

                                    const revenueByCategory = revenueByCategoryResults.map(row => ({
                                        category: row.category,
                                        revenue: row.revenue,
                                    }));

                                    const expensesByCategory = expensesByCategoryResults.map(row => ({
                                        category: row.category,
                                        total_expense: row.total_expense,
                                    }));

                                    const previousRevenue = previousRevenueResults[0].revenue || 0;
                                    const previousCostOfGoodsSold = previousCogsResults[0].cost_of_goods_sold || 0;
                                    const previousOperatingExpenses = previousExpensesResults[0].operating_expenses || 0;
                                    const previousGrossProfit = previousRevenue - previousCostOfGoodsSold;
                                    const previousNetIncome = previousGrossProfit - previousOperatingExpenses;

                                    const financialReport = {
                                        revenue,
                                        costOfGoodsSold,
                                        grossProfit,
                                        operatingExpenses,
                                        netIncome,
                                        revenueByCategory,
                                        expensesByCategory,
                                        previousRevenue,
                                        previousCostOfGoodsSold,
                                        previousOperatingExpenses,
                                        previousNetIncome,
                                    };

                                    res.json(financialReport);
                                });
                            });
                        });
                    });
                });
            });
        });
    });
});


// Ruta para obtener todos los gastos operativos
app.get('/expenses', verifySession, (req, res) => {
    const query = 'SELECT * FROM expenses';
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching expenses:', err);
            return res.status(500).send('Server error');
        }
        res.json(results);
    });
});

// Ruta para agregar un nuevo gasto operativo
app.post('/expenses', verifySession, (req, res) => {
    const { description, amount, date, category } = req.body;
    const query = 'INSERT INTO expenses (description, amount, date, category) VALUES (?, ?, ?, ?)';
    db.query(query, [description, amount, date, category], (err, results) => {
        if (err) {
            console.error('Error adding expense:', err);
            return res.status(500).send('Server error');
        }
        res.status(201).send('Expense added');
    });
});


app.put('/expenses/:id', verifySession, (req, res) => {
    const { id } = req.params;
    const { description, amount, date, category } = req.body;
    const query = 'UPDATE expenses SET description = ?, amount = ?, date = ?, category = ? WHERE expense_id = ?';
    db.query(query, [description, amount, date, category, id], (err, results) => {
        if (err) {
            console.error('Error updating expense:', err);
            return res.status(500).send('Server error');
        }
        res.send('Expense updated');
    });
});

app.delete('/expenses/:id', verifySession, (req, res) => {
    const { id } = req.params;
    const query = 'DELETE FROM expenses WHERE expense_id = ?';
    db.query(query, [id], (err, results) => {
        if (err) {
            console.error('Error deleting expense:', err);
            return res.status(500).send('Server error');
        }
        res.send('Expense deleted');
    });
});


const reportsDirectoryProducts = path.join(__dirname, 'reports-products');
if (!fs.existsSync(reportsDirectoryProducts)) {
    fs.mkdirSync(reportsDirectoryProducts);
}

// Configura el cron job para que se ejecute diariamente a medianoche
cron.schedule('10 * * * *', async () => { // Ejecuta diariamente a medianoche
    try {
        console.log('Generando reporte automático de productos...');

        const token = 'tu_token_aqui'; // Cambia esto por tu token real
        const queryString = new URLSearchParams({
            fields: 'name,description,price,stock,category',
            filter: ''
        }).toString();

        const response = await axios.get(`http://localhost:3001/generate-product-report?${queryString}`, {
            headers: { Authorization: `Bearer ${token}` },
            responseType: 'arraybuffer' // Usa 'arraybuffer' para manejar el PDF
        });

        // Guarda el PDF en el directorio de reportes de productos
        const fileName = `product_report_${new Date().toISOString().replace(/[:.]/g, '-')}.pdf`;
        const filePath = path.join(reportsDirectoryProducts, fileName);
        fs.writeFileSync(filePath, response.data);
        console.log(`Reporte generado y guardado como ${fileName}`);
    } catch (error) {
        console.error('Error generando el reporte automático de productos:', error);
    }
});

// Endpoint para generar reportes de productos
app.get('/generate-product-report', (req, res) => {
    const { fields, filter } = req.query;

    const defaultFields = ['name', 'description', 'price', 'stock', 'category'];
    const selectedFields = fields ? fields.split(',') : defaultFields;

    let query = 'SELECT ' + selectedFields.join(', ') + ' FROM Products';
    if (filter) {
        query += ` WHERE ${filter}`;
    }

    db.query(query, (err, results) => {
        if (err) {
            console.error('Error al ejecutar la consulta:', err);
            return res.status(500).send('Server error');
        }

        const doc = new PDFDocument({ margin: 50 });
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const fileName = `product_report_${timestamp}.pdf`;
        const filePath = path.join(reportsDirectoryProducts, fileName);
        const stream = fs.createWriteStream(filePath);
        doc.pipe(stream);

        // Encabezado del documento
        doc.fontSize(16).text('Informe de Productos', { align: 'center', underline: true });
        doc.moveDown(1);

        // Configuración de la tabla
        const tableTop = 100;
        const columnWidth = 100; // Ajusta el ancho de las columnas si es necesario
        const totalWidth = selectedFields.length * columnWidth; // Ancho total de la tabla
        let currentY = tableTop;

        // Encabezados de la tabla
        doc.fontSize(10).font('Helvetica-Bold');
        selectedFields.forEach((field, index) => {
            doc.text(field.replace('_', ' ').toUpperCase(), 50 + index * columnWidth, currentY, {
                width: columnWidth,
                align: 'center'
            });
        });

        // Línea divisoria de encabezado
        currentY += 20;
        doc.moveTo(50, currentY)
           .lineTo(50 + totalWidth, currentY)
           .stroke();

        // Filas de la tabla
        doc.font('Helvetica').fontSize(9);
        results.forEach((product) => {
            let maxLineCount = 1;

            selectedFields.forEach((field, index) => {
                const text = product[field] ? product[field].toString() : '';
                const lines = doc.heightOfString(text, {
                    width: columnWidth,
                    align: 'center'
                }) / doc.currentLineHeight();

                if (lines > maxLineCount) {
                    maxLineCount = lines;
                }
            });

            selectedFields.forEach((field, index) => {
                const text = product[field] ? product[field].toString() : '';
                doc.text(text, 50 + index * columnWidth, currentY, {
                    width: columnWidth,
                    align: 'center'
                });
            });

            currentY += maxLineCount * doc.currentLineHeight() + 8;

            // Línea divisoria después de cada fila
            doc.moveTo(50, currentY)
               .lineTo(50 + totalWidth, currentY)
               .stroke();
        });

        // Espacio adicional antes del pie de página
        currentY += 20;

        // Pie de página
        doc.fontSize(8).text(`Fecha: ${new Date().toLocaleDateString()}`, 50, currentY, {
            align: 'right'
        });

        doc.end();

        stream.on('finish', () => {
            res.download(filePath, fileName, (err) => {
                if (err) {
                    console.error('Error al descargar el archivo:', err);
                    res.status(500).send('Server error');
                }
            });
        });
    });
});


// Endpoint para listar reportes pasados
app.get('/past-reports-products', (req, res) => {
    fs.readdir(reportsDirectoryProducts, (err, files) => {
        if (err) {
            console.error('Error al leer el directorio de reportes:', err);
            return res.status(500).send('Server error');
        }

        // Genera una lista de reportes con nombre y URL
        const reports = files.map(file => {
            // Extrae la fecha del nombre del archivo para mostrarla en el frontend
            const dateMatch = file.match(/product_report_(\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{3}Z)/);
            const date = dateMatch ? dateMatch[1].replace(/-/g, ':') : 'Desconocida'; // Cambia ':' por '-' para formato amigable

            return {
                id: file,
                name: file,
                date: date,
                url: `/reports-products/${file}` // Asegúrate de que la ruta sea correcta
            };
        });

        res.json(reports);
    });
});

// Servir archivos estáticos desde el directorio de reportes
app.use('/reports-products', express.static(reportsDirectoryProducts));

const reportsDirectory = path.join(__dirname, 'reports');
if (!fs.existsSync(reportsDirectory)) {
    fs.mkdirSync(reportsDirectory);
}

app.get('/generate-inventory-report', (req, res) => {
    const { fields, name, category, price_min, price_max, format } = req.query;
    const selectedFields = fields.split(',');

    // Consulta de productos a la base de datos utilizando db.query con callbacks
    db.query(`
        SELECT ${selectedFields.join(', ')} FROM products 
        WHERE name LIKE ? AND category LIKE ? 
        AND price BETWEEN ? AND ?
    `, [`%${name}%`, `%${category}%`, price_min, price_max], (err, products) => {
        if (err) {
            console.error('Error al ejecutar la consulta:', err);
            return res.status(500).send('Error en el servidor');
        }

        if (format === 'pdf') {
            const doc = new PDFDocument();
            const fileName = `inventory_report_${new Date().toISOString().replace(/[:.]/g, '-')}.pdf`;
            const filePath = path.join(reportsDirectory, fileName);
            const stream = fs.createWriteStream(filePath);
            doc.pipe(stream);

            // Cabecera del reporte
            doc.fontSize(18).text('Informe de Inventario', { align: 'center' });
            doc.moveDown(2);

            // Tabla de productos
            const tableTop = 100;
            const columnWidth = 150;
            let currentY = tableTop;

            doc.fontSize(12).font('Helvetica-Bold');
            selectedFields.forEach((field, index) => {
                doc.text(field.toUpperCase(), 50 + index * columnWidth, currentY, { width: columnWidth });
            });

            doc.moveTo(50, currentY + 20).lineTo(50 + selectedFields.length * columnWidth, currentY + 20).stroke();

            doc.font('Helvetica').fontSize(10);
            products.forEach((product) => {
                selectedFields.forEach((field, index) => {
                    const text = product[field] ? product[field].toString() : '';
                    doc.text(text, 50 + index * columnWidth, currentY + 30, { width: columnWidth });
                });
                currentY += 30;
            });

            doc.end();
            stream.on('finish', () => res.download(filePath));

        } else if (format === 'csv') {
            const fields = selectedFields.map(field => field.toUpperCase());
            const parser = new Parser({ fields });
            const csv = parser.parse(products);
            const fileName = `inventory_report_${new Date().toISOString().replace(/[:.]/g, '-')}.csv`;
            const filePath = path.join(reportsDirectory, fileName);
            fs.writeFileSync(filePath, csv);
            res.download(filePath);

        } else if (format === 'xlsx') {
            const workbook = new ExcelJS.Workbook();
            const worksheet = workbook.addWorksheet('Reporte de Inventario');
            worksheet.columns = selectedFields.map(field => ({ header: field.toUpperCase(), key: field, width: 20 }));

            products.forEach((product) => worksheet.addRow(product));
            const fileName = `inventory_report_${new Date().toISOString().replace(/[:.]/g, '-')}.xlsx`;
            const filePath = path.join(reportsDirectory, fileName);
            workbook.xlsx.writeFile(filePath).then(() => {
                res.download(filePath);
            });

        } else {
            res.status(400).send('Formato no soportado');
        }
    });
});

module.exports = app;
const reportsDirectoryUsers = path.join(__dirname, 'reports-users');
if (!fs.existsSync(reportsDirectoryUsers)) {
    fs.mkdirSync(reportsDirectoryUsers);
}

// Endpoint para generar reportes en PDF, CSV o Excel
app.get('/generate-user-report', verifySession, (req, res) => {
    const { fields, filter, format = 'pdf' } = req.query; // Formato por defecto 'pdf'

    const defaultFields = ['username', 'email', 'created_at'];
    const selectedFields = fields ? fields.split(',') : defaultFields;

    let query = 'SELECT ' + selectedFields.join(', ') + ' FROM Users';
    if (filter) {
        query += ` WHERE ${filter}`;
    }

    db.query(query, (err, results) => {
        if (err) {
            console.error('Error al ejecutar la consulta:', err);
            return res.status(500).send('Server error');
        }

        if (format === 'pdf') {
            // Generar PDF
            const doc = new PDFDocument({ margin: 50 });
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const fileName = `user_report_${timestamp}.pdf`;
            const filePath = path.join(reportsDirectoryUsers, fileName);
            const stream = fs.createWriteStream(filePath);
            doc.pipe(stream);

            // Encabezado del documento
            doc.fontSize(18).text('Informe de Usuarios', { align: 'center', underline: true });
            doc.moveDown(2);

            // Configuración de la tabla
            const tableTop = 100;
            const columnWidth = 150;
            let currentY = tableTop;

            // Encabezados de la tabla
            doc.fontSize(12).font('Helvetica-Bold');
            selectedFields.forEach((field, index) => {
                doc.text(field.replace('_', ' ').toUpperCase(), 50 + index * columnWidth, currentY, {
                    width: columnWidth,
                    align: 'center'
                });
            });

            // Línea divisoria de encabezado
            currentY += 20;
            doc.moveTo(50, currentY)
                .lineTo(50 + selectedFields.length * columnWidth, currentY)
                .stroke();

            // Filas de la tabla
            doc.font('Helvetica').fontSize(10);
            results.forEach((user) => {
                selectedFields.forEach((field, index) => {
                    const text = user[field] ? user[field].toString() : '';
                    doc.text(text, 50 + index * columnWidth, currentY, {
                        width: columnWidth,
                        align: 'center'
                    });
                });
                currentY += doc.currentLineHeight() + 10;

                // Línea divisoria después de cada fila
                doc.moveTo(50, currentY)
                    .lineTo(50 + selectedFields.length * columnWidth, currentY)
                    .stroke();
            });

            // Pie de página
            currentY += 20;
            doc.fontSize(10).text(`Fecha: ${new Date().toLocaleDateString()}`, 50, currentY, { align: 'right' });
            doc.end();

            stream.on('finish', () => {
                res.download(filePath, fileName, (err) => {
                    if (err) {
                        console.error('Error al descargar el archivo:', err);
                        res.status(500).send('Server error');
                    }
                });
            });
        } else if (format === 'csv') {
            // Generar CSV
            const fields = selectedFields.map(field => field.replace('_', ' '));
            const parser = new Parser({ fields });
            const csv = parser.parse(results);
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const fileName = `user_report_${timestamp}.csv`;
            const filePath = path.join(reportsDirectoryUsers, fileName);

            fs.writeFile(filePath, csv, (err) => {
                if (err) {
                    console.error('Error al generar CSV:', err);
                    return res.status(500).send('Server error');
                }
                res.download(filePath, fileName, (err) => {
                    if (err) {
                        console.error('Error al descargar CSV:', err);
                        res.status(500).send('Server error');
                    }
                });
            });
        } else if (format === 'excel') {
            // Generar Excel
            const workbook = new ExcelJS.Workbook();
            const worksheet = workbook.addWorksheet('Reporte de Usuarios');

            // Añadir encabezados
            worksheet.columns = selectedFields.map(field => ({
                header: field.replace('_', ' ').toUpperCase(),
                key: field,
                width: 20
            }));

            // Añadir datos
            results.forEach(user => {
                worksheet.addRow(user);
            });

            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const fileName = `user_report_${timestamp}.xlsx`;
            const filePath = path.join(reportsDirectoryUsers, fileName);

            workbook.xlsx.writeFile(filePath)
                .then(() => {
                    res.download(filePath, fileName, (err) => {
                        if (err) {
                            console.error('Error al descargar Excel:', err);
                            res.status(500).send('Server error');
                        }
                    });
                })
                .catch((err) => {
                    console.error('Error al generar Excel:', err);
                    res.status(500).send('Server error');
                });
        } else {
            return res.status(400).send('Formato no soportado');
        }
    });
});

// Endpoint para listar reportes pasados
app.get('/past-reports-users', verifySession, (req, res) => {
    fs.readdir(reportsDirectoryUsers, (err, files) => {
        if (err) {
            console.error('Error al leer el directorio de reportes:', err);
            return res.status(500).send('Server error');
        }

        // Genera una lista de reportes con nombre y URL
        const reports = files.map(file => {
            // Extrae la fecha del nombre del archivo para mostrarla en el frontend
            const dateMatch = file.match(/user_report_(\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{3}Z)/);
            const date = dateMatch ? dateMatch[1].replace(/-/g, ':') : 'Desconocida';

            return {
                id: file,
                name: file,
                date: date,
                url: `/reports-users/${file}`
            };
        });

        res.json(reports);
    });
});

// Servir archivos estáticos desde el directorio de reportes
app.use('/reports-users', express.static(reportsDirectoryUsers));

module.exports = app;

// Directorio de reportes de clientes
const reportsDirectoryClients = path.join(__dirname, 'reports-clients');
if (!fs.existsSync(reportsDirectoryClients)) {
    fs.mkdirSync(reportsDirectoryClients);
}

// Configura el cron job para que se ejecute diariamente
cron.schedule('10 10 * * *', async () => {
    try {
        console.log('Generando reporte automático...');

        const token = 'tu_token_aqui'; 
        const queryString = new URLSearchParams({
            fields: 'name,address,contact_info', 
            filter: '',
            start_date: '', 
            end_date: ''
        }).toString();

        const response = await axios.get(`http://localhost:3001/generate-client-report?${queryString}`, {
            headers: { Authorization: `Bearer ${token}` },
            responseType: 'arraybuffer' // Usa 'arraybuffer' para manejar el PDF
        });

    
    } catch (error) {
        console.error('Error generando el reporte automático:', error);
    }
});

// Endpoint para generar reportes de clientes
app.get('/generate-client-report', (req, res) => {
    const { fields, filter, start_date, end_date } = req.query;

    const defaultFields = ['name', 'address', 'contact_info'];
    const selectedFields = fields ? fields.split(',') : defaultFields;

    let query = 'SELECT ' + selectedFields.join(', ') + ' FROM Clients';
    if (filter) {
        query += ` WHERE ${filter}`;
    }
    if (start_date) {
        query += ` AND date >= '${start_date}'`;
    }
    if (end_date) {
        query += ` AND date <= '${end_date}'`;
    }

    db.query(query, (err, results) => {
        if (err) {
            console.error('Error al ejecutar la consulta:', err);
            return res.status(500).send('Server error');
        }

        if (results.length === 0) {
            return res.status(404).send('No data found');
        }

        const doc = new PDFDocument({ margin: 50 });
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const fileName = `client_report_${timestamp}.pdf`;
        const filePath = path.join(reportsDirectoryClients, fileName);
        const stream = fs.createWriteStream(filePath);
        doc.pipe(stream);

        // Encabezado del documento
        doc.fontSize(18).text('Informe de Clientes', { align: 'center', underline: true });
        doc.moveDown(2);

        // Configuración de la tabla
        const tableTop = 100;
        const tableLeft = 50;
        const columnWidth = 150;
        let currentY = tableTop;

        // Encabezados de la tabla
        doc.fontSize(12).font('Helvetica-Bold');
        selectedFields.forEach((field, index) => {
            doc.text(field.replace('_', ' ').toUpperCase(), tableLeft + index * columnWidth, currentY, {
                width: columnWidth,
                align: 'center'
            });
        });

        // Líneas de encabezado
        currentY += 20;
        doc.moveTo(tableLeft, currentY)
           .lineTo(tableLeft + selectedFields.length * columnWidth, currentY)
           .stroke();

        // Filas de la tabla
        doc.font('Helvetica').fontSize(10);

        results.forEach((item) => {
            let maxLineCount = 1;

            selectedFields.forEach((field, index) => {
                const text = item[field] ? item[field].toString() : '';
                const lines = doc.heightOfString(text, {
                    width: columnWidth,
                    align: 'center'
                }) / doc.currentLineHeight();

                if (lines > maxLineCount) {
                    maxLineCount = lines;
                }
            });

            selectedFields.forEach((field, index) => {
                const text = item[field] ? item[field].toString() : '';
                doc.text(text, tableLeft + index * columnWidth, currentY, {
                    width: columnWidth,
                    align: 'center'
                });
            });

            currentY += maxLineCount * doc.currentLineHeight() + 10;

            // Líneas divisorias
            doc.moveTo(tableLeft, currentY)
               .lineTo(tableLeft + selectedFields.length * columnWidth, currentY)
               .stroke();
        });

        // Espacio adicional antes de la fecha
        currentY += 20;

        // Pie de página
        doc.fontSize(10).text(`Fecha: ${new Date().toLocaleDateString()}`, tableLeft, currentY, {
            align: 'right'
        });

        doc.end();

        stream.on('finish', () => {
            res.download(filePath, fileName, (err) => {
                if (err) {
                    console.error('Error al descargar el archivo:', err);
                    res.status(500).send('Server error');
                }
                // Nota: El archivo se guarda en el directorio de reportes pasados, no se elimina aquí
            });
        });
    });
});

// Endpoint para listar reportes pasados
app.get('/past-reports-clients', (req, res) => {
    fs.readdir(reportsDirectoryClients, (err, files) => {
        if (err) {
            console.error('Error al leer el directorio de reportes:', err);
            return res.status(500).send('Server error');
        }

        // Genera una lista de reportes con nombre y URL
        const reports = files.map(file => {
            // Extrae la fecha del nombre del archivo para mostrarla en el frontend
            const dateMatch = file.match(/client_report_(\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{3}Z)/);
            const date = dateMatch ? dateMatch[1].replace(/-/g, ':') : 'Desconocida'; // Cambia ':' por '-' para formato amigable

            return {
                id: file,
                name: file,
                date: date,
                url: `/reports-clients/${file}` // Asegúrate de que la ruta sea correcta
            };
        });

        res.json(reports);
    });
});

// Servir archivos estáticos desde el directorio de reportes
app.use('/reports-clients', express.static(reportsDirectoryClients));


// Directorio de reportes ventas
const reportsDirectorySales = path.join(__dirname, 'reports-sales');
if (!fs.existsSync(reportsDirectorySales)) {
    fs.mkdirSync(reportsDirectorySales);
}

// Configura el cron job para que se ejecute diariamente
cron.schedule('10 10 * * *', async () => {
    try {
        console.log('Generando reporte automático...');

        
        const token = 'tu_token_aqui'; 
        const queryString = new URLSearchParams({
            fields: 'description,quantity,unit_price', 
            filter: '',
            start_date: '', 
            end_date: ''
        }).toString();

        const response = await axios.get(`http://localhost:3001/generate-ventas-report?${queryString}`, {
            headers: { Authorization: `Bearer ${token}` },
            responseType: 'blob'
        });

        if (response.status === 200) {
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const fileName = `sales_report_${timestamp}.pdf`;
            const filePath = path.join(reportsDirectorySales, fileName);

            // Guarda el archivo
            fs.writeFileSync(filePath, response.data);
            console.log(`Reporte generado y guardado como ${fileName}`);
        } else {
            console.error('Error en la respuesta:', response);
        }
    } catch (error) {
        console.error('Error generando el reporte automático:', error);
    }
});


app.get('/generate-ventas-report', (req, res) => {
    const { fields, filter, start_date, end_date } = req.query;

    const defaultFields = ['description', 'quantity', 'unit_price'];
    const selectedFields = fields ? fields.split(',') : defaultFields;

    let query = 'SELECT ' + selectedFields.join(', ') + ' FROM SaleItems';
    if (filter) {
        query += ` WHERE ${filter}`;
    }
    if (start_date) {
        query += ` AND date >= '${start_date}'`;
    }
    if (end_date) {
        query += ` AND date <= '${end_date}'`;
    }

    db.query(query, (err, results) => {
        if (err) {
            console.error('Error al ejecutar la consulta:', err);
            return res.status(500).send('Server error');
        }

        const doc = new PDFDocument({ margin: 50 });
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const fileName = `sales_report_${timestamp}.pdf`;
        const filePath = path.join(reportsDirectorySales, fileName);
        const stream = fs.createWriteStream(filePath);
        doc.pipe(stream);

        // Encabezado del documento
        doc.fontSize(18).text('Informe de Ventas', { align: 'center', underline: true });
        doc.moveDown(2);

        // Configuración de la tabla
        const tableTop = 100;
        const tableLeft = 50;
        const columnWidth = 150;
        let currentY = tableTop;

        // Encabezados de la tabla
        doc.fontSize(12).font('Helvetica-Bold');
        selectedFields.forEach((field, index) => {
            doc.text(field.replace('_', ' ').toUpperCase(), tableLeft + index * columnWidth, currentY, {
                width: columnWidth,
                align: 'center'
            });
        });

        // Líneas de encabezado
        currentY += 20;
        doc.moveTo(tableLeft, currentY)
           .lineTo(tableLeft + selectedFields.length * columnWidth, currentY)
           .stroke();

        // Filas de la tabla
        doc.font('Helvetica').fontSize(10);

        results.forEach((item, i) => {
            let maxLineCount = 1;

            selectedFields.forEach((field, index) => {
                const text = item[field] ? item[field].toString() : '';
                const lines = doc.heightOfString(text, {
                    width: columnWidth,
                    align: 'center'
                }) / doc.currentLineHeight();

                if (lines > maxLineCount) {
                    maxLineCount = lines;
                }
            });

            selectedFields.forEach((field, index) => {
                const text = item[field] ? item[field].toString() : '';
                doc.text(text, tableLeft + index * columnWidth, currentY, {
                    width: columnWidth,
                    align: 'center'
                });
            });

            currentY += maxLineCount * doc.currentLineHeight() + 10;

            // Líneas divisorias
            doc.moveTo(tableLeft, currentY)
               .lineTo(tableLeft + selectedFields.length * columnWidth, currentY)
               .stroke();
        });

        // Espacio adicional antes de la fecha
        currentY += 20;

        // Pie de página
        doc.fontSize(10).text(`Fecha: ${new Date().toLocaleDateString()}`, tableLeft, currentY, {
            align: 'right'
        });

        doc.end();

        stream.on('finish', () => {
            res.download(filePath, fileName, (err) => {
                if (err) {
                    console.error('Error al descargar el archivo:', err);
                    res.status(500).send('Server error');
                }
                // Nota: El archivo se guarda en el directorio de reportes pasados, no se elimina aquí
            });
        });
    });
});


// Endpoint para listar reportes pasados
app.get('/past-reports-sales', (req, res) => {
    fs.readdir(reportsDirectorySales, (err, files) => {
        if (err) {
            console.error('Error al leer el directorio de reportes:', err);
            return res.status(500).send('Server error');
        }

        // Genera una lista de reportes con nombre y URL
        const reports = files.map(file => {
            // Extrae la fecha del nombre del archivo para mostrarla en el frontend
            const dateMatch = file.match(/sales_report_(\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{3}Z)/);
            const date = dateMatch ? dateMatch[1].replace(/-/g, ':') : 'Desconocida'; // Cambia ':' por '-' para formato amigable

            return {
                id: file,
                name: file,
                date: date,
                url: `/reports-sales/${file}` // Asegúrate de que la ruta sea correcta
            };
        });

        res.json(reports);
    });
});

// Servir archivos estáticos desde el directorio de reportes
app.use('/reports-sales', express.static(reportsDirectorySales));


app.get('/suppliers', verifySession, (req, res) => {
    db.query('SELECT * FROM Suppliers', (err, results) => {
        if (err) {
            console.error('Error fetching suppliers:', err);
            res.status(500).send('Server error');
            return;
        }
        res.json(results);
    });
});

app.get('/suppliers/:id', verifySession, (req, res) => {
    const { id } = req.params;
    db.query('SELECT * FROM Suppliers WHERE supplier_id = ?', [id], (err, results) => {
        if (err) {
            console.error('Error fetching supplier:', err);
            return res.status(500).send('Server error');
        }
        if (results.length === 0) {
            return res.status(404).send('Supplier not found');
        }
        res.json(results[0]);
    });
});

app.post('/suppliers', verifySession, (req, res) => {
    const { name, contact, address, payment_terms } = req.body;
    const query = 'INSERT INTO Suppliers (name, contact, address, payment_terms) VALUES (?, ?, ?, ?)';
    db.query(query, [name, contact, address, payment_terms], (err, results) => {
        if (err) {
            console.error('Error adding supplier:', err);
            return res.status(500).send('Server error');
        }
        res.status(201).send('Supplier added');
    });
});

app.put('/suppliers/:id', verifySession, (req, res) => {
    const { id } = req.params;
    const { name, contact, address, payment_terms } = req.body;
    const query = 'UPDATE Suppliers SET name = ?, contact = ?, address = ?, payment_terms = ? WHERE supplier_id = ?';
    db.query(query, [name, contact, address, payment_terms, id], (err, results) => {
        if (err) {
            console.error('Error updating supplier:', err);
            return res.status(500).send('Server error');
        }
        res.send('Supplier updated');
    });
});

app.delete('/suppliers/:id', verifySession, (req, res) => {
    const { id } = req.params;
    const query = 'DELETE FROM Suppliers WHERE supplier_id = ?';
    db.query(query, [id], (err, results) => {
        if (err) {
            console.error('Error deleting supplier:', err);
            return res.status(500).send('Server error');
        }
        res.send('Supplier deleted');
    });
});




app.get('/admin/orders', verifySession, (req, res) => {
    const query = 'SELECT * FROM Orders';
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching orders:', err);
            return res.status(500).send('Server error');
        }
        res.status(200).json(results);
    });
});

app.get('/admin/orders/:orderId', verifySession, (req, res) => {
    const orderId = req.params.orderId;
    
    const orderQuery = `
        SELECT orders.*, clients.name AS client_name, clients.address, clients.email, clients.contact_info
        FROM orders
        JOIN clients ON orders.client_id = clients.client_id
        WHERE orders.order_id = ?
    `;
    
    const itemsQuery = `
        SELECT orderitems.*, products.name AS product_name
        FROM orderitems
        JOIN products ON orderitems.product_id = products.product_id
        WHERE orderitems.order_id = ?
    `;
    
    db.query(orderQuery, [orderId], (err, orderResult) => {
        if (err) {
            console.error('Error fetching order details:', err);
            return res.status(500).send('Error fetching order details');
        }
        if (orderResult.length === 0) {
            return res.status(404).send('Order not found');
        }

        const order = orderResult[0];

        db.query(itemsQuery, [orderId], (err, itemsResult) => {
            if (err) {
                console.error('Error fetching order items:', err);
                return res.status(500).send('Error fetching order items');
            }
            order.items = itemsResult;
            res.json(order);
        });
    });
});


app.put('/admin/orders/:orderId/approve', verifySession, (req, res) => {
    const orderId = req.params.orderId;

    const updateOrderQuery = `UPDATE orders SET status = 'completed' WHERE order_id = ?`;

    db.query(updateOrderQuery, [orderId], (err, result) => {
        if (err) {
            console.error('Error updating order status:', err);
            return res.status(500).json({ error: 'Error updating order status' });
        }

        const getOrderDetailsQuery = `
            SELECT o.*, c.name AS client_name, c.email, c.address, c.contact_info,
                   oi.product_id, p.name AS product_name, oi.quantity, oi.unit_price, p.discount, o.stripe_session_id
            FROM orders o
            JOIN clients c ON o.client_id = c.client_id
            JOIN orderitems oi ON o.order_id = oi.order_id
            JOIN products p ON oi.product_id = p.product_id
            WHERE o.order_id = ?
        `;

        db.query(getOrderDetailsQuery, [orderId], (err, orderDetails) => {
            if (err) {
                console.error('Error fetching order details:', err);
                return res.status(500).json({ error: 'Error fetching order details' });
            }
            if (orderDetails.length === 0) {
                return res.status(404).send('Order not found');
            }

            const order = orderDetails[0];

            const createInvoiceQuery = `
                INSERT INTO invoices (client_id, order_id, issue_date, due_date, total_amount, status, payment_method)
                VALUES (?, ?, NOW(), DATE_ADD(NOW(), INTERVAL 30 DAY), ?, 'approved', ?)
            `;

            db.query(createInvoiceQuery, [order.client_id, orderId, order.total_amount, 'not specified'], (err, invoiceResult) => {
                if (err) {
                    console.error('Error creating invoice:', err);
                    return res.status(500).json({ error: 'Error creating invoice' });
                }

                const invoiceId = invoiceResult.insertId;

                const invoiceItems = orderDetails.map(item => [
                    invoiceId, item.product_id, item.product_name, item.quantity, item.unit_price, item.discount, (item.unit_price * item.quantity)
                ]);

                const insertInvoiceItemsQuery = `
                    INSERT INTO invoiceitems (invoice_id, product_id, description, quantity, unit_price, discount, subtotal)
                    VALUES ?
                `;

                db.query(insertInvoiceItemsQuery, [invoiceItems], (err) => {
                    if (err) {
                        console.error('Error inserting invoice items:', err);
                        return res.status(500).json({ error: 'Error inserting invoice items' });
                    }

                    // Generar el PDF de la factura
                    const doc = new PDFDocument();
                    const pdfPath = path.join(__dirname, `factura_${invoiceId}.pdf`);
                    doc.pipe(fs.createWriteStream(pdfPath));

                    doc.fontSize(25).text('Factura Electrónica', { align: 'center' });
                    doc.moveDown();
                    doc.fontSize(14).text(`Factura ID: ${invoiceId}`);
                    doc.text(`Fecha: ${new Date().toLocaleDateString()}`);
                    doc.moveDown();
                    doc.text(`Cliente: ${order.client_name}`);
                    doc.text(`Dirección: ${order.address}`);
                    doc.text(`Email: ${order.email}`);
                    doc.text(`Teléfono: ${order.contact_info}`);
                    doc.moveDown();
                    doc.text('Detalles de la Orden:', { underline: true });

                    invoiceItems.forEach((item, index) => {
                        doc.text(`${index + 1}. Producto: ${item[2]}`);
                        doc.text(`Cantidad: ${item[3]}`);
                        doc.text(`Precio Unitario: ${item[4]}`);
                        doc.text(`Descuento: ${item[5]}`);
                        doc.text(`Subtotal: ${item[6]}`);
                        doc.moveDown();
                    });

                    doc.text(`Total: ${order.total_amount}`, { align: 'right' });
                    doc.end();

                    const mailOptions = {
                        from: 'duant75@gmail.com',
                        to: order.email,
                        subject: `Factura de su orden #${orderId}`,
                        text: `Estimado ${order.client_name},\n\nAdjunto encontrará la factura de su orden.\n\nGracias por su compra.`,
                        attachments: [
                            {
                                filename: `Factura_${invoiceId}.pdf`,
                                path: pdfPath,
                                contentType: 'application/pdf'
                            }
                        ]
                    };                

                    transporter.sendMail(mailOptions, (error, info) => {
                        if (error) {
                            console.error('Error sending email:', error);
                            return res.status(500).json({ error: 'Error sending email' });
                        }
                        console.log('Email sent: ' + info.response);
                        res.json({ success: true, invoiceId });
                    });
                });
            });
        });
    });
});


app.get('/admin/invoices', verifySession, (req, res) => {
    const query = `
        SELECT 
            i.invoice_id, 
            i.issue_date, 
            i.due_date, 
            i.total_amount, 
            i.status, 
            i.payment_method, 
            i.tax, 
            i.subtotal, 
            o.order_id, 
            c.name AS client_name, 
            c.email AS client_email
        FROM invoices i
        JOIN orders o ON i.order_id = o.order_id
        JOIN clients c ON i.client_id = c.client_id
        WHERE i.order_id IS NOT NULL
    `;
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching invoices:', err);
            return res.status(500).send('Server error');
        }
        res.json(results);
    });
});

app.get('/invoice/:id', verifySession, (req, res) => {
    const invoiceId = req.params.id;

    const queryInvoiceDetails = `
    SELECT 
        i.invoice_id, 
        i.issue_date, 
        i.due_date, 
        i.total_amount, 
        i.status, 
        i.payment_method, 
        i.tax, 
        i.subtotal, 
        c.name AS client_name, 
        c.identification_number AS client_identification, 
        c.address, 
        c.contact_info
    FROM invoices i
    JOIN clients c ON i.client_id = c.client_id
    WHERE i.invoice_id = ?
`;


    const queryInvoiceItems = `
        SELECT 
            ii.item_id, 
            ii.description, 
            ii.quantity, 
            ii.unit_price, 
            ii.subtotal 
        FROM invoiceitems ii
        WHERE ii.invoice_id = ?
    `;

    db.query(queryInvoiceDetails, [invoiceId], (err, invoiceResult) => {
        if (err) {
            console.error('Error fetching invoice details:', err);
            return res.status(500).json({ error: 'Error fetching invoice details' });
        }

        if (invoiceResult.length === 0) {
            return res.status(404).send('Invoice not found');
        }

        const invoice = invoiceResult[0];

        db.query(queryInvoiceItems, [invoiceId], (err, itemsResult) => {
            if (err) {
                console.error('Error fetching invoice items:', err);
                return res.status(500).json({ error: 'Error fetching invoice items' });
            }

            res.json({ invoice, items: itemsResult });
        });
    });
});


app.get('/client-by-user/:user_id', async (req, res) => {  // Corregido: Se eliminó la coma innecesaria
    const { user_id } = req.params;
    db.query('SELECT * FROM Clients WHERE user_id = ?', [user_id], (err, results) => {
        if (err) {
            console.error('Error fetching client by user_id:', err);
            return res.status(500).send('Server error');
        }
        if (results.length === 0) {
            return res.status(404).send('Client not found');
        }
        res.json(results[0]);
    });
});



app.listen(3001, () => {
    console.log('Server is running on port 3001');
});
