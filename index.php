<?php
// index.php

require_once(__DIR__ . '/config/config.php');

// Enable error logging to a file
ini_set('log_errors', 1);
ini_set('error_log', __DIR__ . '/logs/error_log.log');  // Specify the path to your log file

// Serve signin.html as the homepage
if ($_SERVER['REQUEST_URI'] === '/' || $_SERVER['REQUEST_URI'] === '/index.php') {
    // Check if the form is submitted
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        header('Content-Type: application/json'); // Set header for JSON response
        $data = json_decode(file_get_contents('php://input'), true);

        // Check if the email and password are provided
        if (isset($data['email']) && isset($data['password'])) {
            // Echo the payload received from the client
            echo json_encode(['message' => 'Payload received', 'payload' => $data]);

            // Connect to the database
            $conn = connectToDatabase();

            // Prepare and bind
            if ($stmt = $conn->prepare("SELECT id, email, password FROM utenti WHERE email = ?")) {
                $stmt->bind_param("s", $email);

                // Set parameter from data received
                $email = $data['email'];

                // Execute the query
                if ($stmt->execute()) {
                    $result = $stmt->get_result();
                    if ($result->num_rows == 1) {
                        $row = $result->fetch_assoc();
                        $hashed_password = $row['password'];

                        // Echo the database response
                        echo json_encode(['message' => 'Database response', 'response' => $row]);

                        // Verify the password
                        if (password_verify($data['password'], $hashed_password)) {
                            // Password is correct, create a session
                            
                            session_start();
                            $_SESSION['user_id'] = $row['id'];
                            // echo json_encode(['message' => 'Login successful', 'redirect' => '/public/dashboard/dashboard.html']);
                            exit(); // Stop further execution
                        } else {
                            // Password is incorrect
                            http_response_code(401); // Unauthorized
                            $logMessage = "Incorrect password for email: " . $data['email'];
                            error_log($logMessage); // Log the message to the error log
                            echo json_encode(['message' => 'Incorrect email or password']);
                            exit(); // Stop further execution
                        }
                    } else {
                        // No user found with the provided email
                        http_response_code(404); // Not Found
                        $logMessage = "User not found for email: " . $data['email'];
                        error_log($logMessage); // Log the message to the error log
                        echo json_encode(['message' => 'User not found']);
                        exit(); // Stop further execution
                    }
                } else {
                    http_response_code(500); // Internal Server Error
                    echo json_encode(['message' => 'Failed to execute query', 'error' => $stmt->error]);
                    exit(); // Stop further execution
                }

                // $stmt->close();
            } else {
                http_response_code(500); // Internal Server Error
                echo json_encode(['message' => 'Failed to prepare statement', 'error' => $conn->error]);
                exit(); // Stop further execution
            }

            // $conn->close();
        } else {
            // Email or password not provided
            http_response_code(400); // Bad Request
            echo json_encode(['message' => 'Email and password are required']);
            exit(); // Stop further execution
        }
    } else {
        include_once(__DIR__ . '/public/auth_pages/login.html');
        exit();
    }
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