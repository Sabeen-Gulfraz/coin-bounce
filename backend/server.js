const express = require('express');
const dbConnect = require('./database/index');
const {PORT} = require('./config/index');
const router = require('./routes/index');
const errorHandler = require('./middlewares/errorHandlers');
const cookieParser = require('cookie-parser');

const app = express();

app.use(cookieParser());

app.use(router);

dbConnect();

app.use('/storage', express.static('storage'));   

app.use(express.json());

app.use(errorHandler);

app.listen(PORT, console.log(`Backend is running on port: ${PORT}`));