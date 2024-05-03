<?php
// index.php

require_once(__DIR__ . '/config/config.php');

// Serve signin.html as the homepage
if ($_SERVER['REQUEST_URI'] === '/' || $_SERVER['REQUEST_URI'] === '/index.php') {
    include_once(__DIR__ . '/public/auth_pages/login.html');
    exit();
}

// Handle the register route
if ($_SERVER['REQUEST_URI'] === '/register') {
    if ($_SERVER['REQUEST_METHOD'] === 'GET') {
        include_once(__DIR__ . '/public/auth_pages/signup.html');
        exit();
    } elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
        header('Content-Type: application/json'); // Set header for JSON response
        $data = json_decode(file_get_contents('php://input'), true);

        // Connect to the database
        $conn = connectToDatabase();

        // Prepare and bind
        if ($stmt = $conn->prepare("INSERT INTO utenti (nome, cognome, email, password) VALUES (?, ?, ?, ?)")) {
            $stmt->bind_param("ssss", $nome, $cognome, $email, $password);

            // Set parameters from data received and hash password
            $nome = $data['nome'];
            $cognome = $data['cognome'];
            $email = $data['email'];
            $password = password_hash($data['password'], PASSWORD_DEFAULT); // Securely hash the password

            if ($stmt->execute()) {
                echo json_encode(['message' => 'Account created successfully', 'redirect' => '/']); // Redirect to the login page
            } else {
                http_response_code(500); // Internal Server Error
                echo json_encode(['message' => 'Failed to create account', 'error' => $stmt->error]);
            }

            $stmt->close();
        } else {
            http_response_code(500); // Internal Server Error
            echo json_encode(['message' => 'Failed to prepare statement', 'error' => $conn->error]);
        }

        $conn->close();
        exit();
    }
}
?>