const mysql = require('mysql2/promise');

const dbConfig = {
    host: 'localhost',
    user: 'root',
    password: 'Temp@2019',
    database: 'tenant_database'
};

async function initializeDb() {
    try {
        const db = await mysql.createConnection(dbConfig);
        console.log('Database connected!');
        return db;
    } catch (err) {
        console.error('Error connecting to the database:', err.message);
        throw err;
    }
}

module.exports = initializeDb;
