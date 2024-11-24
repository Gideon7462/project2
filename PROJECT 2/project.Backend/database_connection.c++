#include <iostream>
#include <mysql/mysql.h>  // MySQL Connector library

//Establishing MySQL connection
MYSQL* connectToDatabase() {
    MYSQL* conn = mysql_init(nullptr);
    if (!conn) {
        std::cerr << "MySQL initialization failed\n";
        exit(1);
    }

    // Connect to the MySQL database
    conn = mysql_real_connect(conn, "localhost", "root", "password", 
                              "TENANT_DATABASE", 3306, nullptr, 0);

    if (conn) {
        std::cout << "Connected to MySQL database successfully.\n";
    } else {
        std::cerr << "Database connection failed: " << mysql_error(conn) << '\n';
        exit(1);
    }

    return conn;
}
