<?php
// config/config.php

// Database configuration settings
define('DB_HOST', 'localhost');         
define('DB_PORT', '3006');              
define('DB_USERNAME', 'root');         
define('DB_PASSWORD', '');      
define('DB_DATABASE', 'Migrations');        

// Function to establish a database connection
function connectToDatabase() {
    $conn = new mysqli(DB_HOST, DB_USERNAME, DB_PASSWORD, DB_DATABASE);

    // Check the connection
    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    }
    return $conn;
}
?>