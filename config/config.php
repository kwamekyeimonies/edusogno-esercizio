<?php
// config/config.php

// Database configuration settings
define('DB_HOST', 'localhost');         // The host of the database
define('DB_PORT', '3306');              // The port MySQL is running on (default is 3306)
define('DB_USERNAME', 'admin');         // The database username
define('DB_PASSWORD', 'admin123');      // The database password
define('DB_DATABASE', 'edusogodb');        // The database name

// Function to establish a database connection
function connectToDatabase() {
    $conn = new mysqli(DB_HOST . ':' . DB_PORT, DB_USERNAME, DB_PASSWORD, DB_DATABASE);

    // Check the connection
    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    }
    return $conn;
}
?>