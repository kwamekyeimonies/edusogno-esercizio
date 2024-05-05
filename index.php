<?php
// index.php

require_once(__DIR__ . '/config/config.php');

require 'PHPMailer/src/PHPMailer.php';
require 'PHPMailer/src/SMTP.php';
require 'PHPMailer/src/Exception.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use PHPMailer\PHPMailer\Exception;

// Enable error logging to a file
error_reporting(E_ALL);
ini_set('display_errors', 1);

$query_string = parse_url($_SERVER['REQUEST_URI'], PHP_URL_QUERY);

// Parse the query string into an associative array of parameters
parse_str($query_string, $params);
// Serve signin.html as the homepage
if ($_SERVER['REQUEST_URI'] === '/' || $_SERVER['REQUEST_URI'] === '/dani/index.php?endpoint=login') {
    // Check if the form is submitted
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        header('Content-Type: application/json'); // Set header for JSON response
        $data = json_decode(file_get_contents('php://input'), true);

        // Check if the email and password are provided
        if (isset($data['email']) && isset($data['password'])) {
            // Connect to the database
            $conn = connectToDatabase();

            // Prepare and bind
            if ($stmt = $conn->prepare("SELECT * FROM utenti WHERE email = ?")) {
                $stmt->bind_param("s", $email);

                // Set parameter from data received
                $email = $data['email'];

                // Execute the query
                if ($stmt->execute()) {
                    $result = $stmt->get_result();
                    if ($result->num_rows == 1) {
                        $row = $result->fetch_assoc();
                        $hashed_password = $row['password'];

                        // Verify the password
                        if (password_verify($data['password'], $hashed_password)) {
                            // Password is correct, create a session
                            session_start();
                            $_SESSION['user_id'] = $row['id'];
                            echo json_encode(['user' => $row, 'redirect' => '../../public/dashboard/dashboard.html']);
                            exit(); // Stop further execution
                        } else {
                            // Password is incorrect
                            http_response_code(401); // Unauthorized
                            echo json_encode(['message' => 'Incorrect email or password']);
                            exit(); // Stop further execution
                        }
                    } else {
                        // No user found with the provided email
                        http_response_code(404); // Not Found
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

if ($_SERVER['REQUEST_URI'] === '/dani/index.php?endpoint=register') {
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

// Handle event submission route
if ($_SERVER['REQUEST_URI'] === '/dani/index.php?endpoint=add_event') {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        header('Content-Type: application/json'); // Set header for JSON response
        $data = json_decode(file_get_contents('php://input'), true);

        // Connect to the database
        $conn = connectToDatabase();

        // Prepare and bind
        if ($stmt = $conn->prepare("INSERT INTO evento (attendees, nome_evento, data_evento) VALUES (?, ?, ?)")) {
            $stmt->bind_param("sss", $attendees, $nome_evento, $data_evento);

            // Set parameters from data received
            $attendees = $data['attendees'];
            $nome_evento = $data['nome_evento'];
            $data_evento = $data['data_evento'];

            if ($stmt->execute()) {
                echo json_encode(['message' => 'Event submitted successfully']);
            } else {
                http_response_code(500); // Internal Server Error
                echo json_encode(['message' => 'Failed to submit event', 'error' => $stmt->error]);
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
// Handle event Update route
if ($_SERVER['REQUEST_URI'] === '/dani/index.php?endpoint=update_event') {
    if ($_SERVER['REQUEST_METHOD'] === 'PUT') {
        header('Content-Type: application/json'); // Set header for JSON response
        $data = json_decode(file_get_contents('php://input'), true);

        // Connect to the database
        $conn = connectToDatabase();

        // Prepare and bind
        if ($stmt = $conn->prepare("UPDATE evento SET  nome_evento = ?, data_evento = ? WHERE id = ?")) {
            $stmt->bind_param("ssi", $nome_evento, $data_evento, $id);

            // Set parameters from data received
            $nome_evento = $data['nome_evento'];
            $data_evento = $data['data_evento'];
            $id = $data['id'];

            if ($stmt->execute()) {
                echo json_encode(['message' => 'Event updated successfully']);
            } else {
                http_response_code(500); // Internal Server Error
                echo json_encode(['error' => 'Failed to submit event', 'error' => $stmt->error]);
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

// Handle event Delete route
if ($params['endpoint']=='delete_event') {
    if ($_SERVER['REQUEST_METHOD'] === 'DELETE') {
        header('Content-Type: application/json'); // Set header for JSON response
        $data = json_decode(file_get_contents('php://input'), true);

        // Connect to the database
        $conn = connectToDatabase();

        // Prepare and bind
        if ($stmt = $conn->prepare("DELETE FROM evento WHERE id = ?")) {
            $stmt->bind_param("i", $id);

            // Set parameters from data received
  
            $id = $params['eventId'];

            if ($stmt->execute()) {
                http_response_code(200); // Internal Server Error

                echo json_encode(['message' => 'Event deleted successfully']);
            } else {
                http_response_code(500); // Internal Server Error
                echo json_encode(['error' => 'Failed to submit event', 'error' => $stmt->error]);
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

// Handle event fetching route
if ($_SERVER['REQUEST_URI'] === '/dani/index.php?endpoint=dashboard') {
    if ($_SERVER['REQUEST_METHOD'] === 'GET') {
        header('Content-Type: application/json'); // Set header for JSON response

        // Connect to the database
        $conn = connectToDatabase();

        // Fetch all events from the database
        $sql = "SELECT * FROM evento";
        $result = $conn->query($sql);

        if ($result) {
            $events = array();
            while ($row = $result->fetch_assoc()) {
                $events[] = $row;
            }
            echo json_encode(['events' => $events]);
        } else {
            http_response_code(500); // Internal Server Error
            echo json_encode(['message' => 'Failed to fetch events', 'error' => $conn->error]);
        }

        $conn->close();
        exit();
    }
}

if ($params['endpoint']=='view_event') {
    if ($_SERVER['REQUEST_METHOD'] === 'GET') {
        header('Content-Type: application/json'); // Set header for JSON response


        // Check if eventId is provided in the query string
        if (isset($params['eventId'])) {
            $eventId = (int)$params['eventId']; // Convert to integer
            // echo json_encode(["id" => $eventId]); // Echo as JSON

            // Connect to the database
            $conn = connectToDatabase();

            // Fetch event details by eventId
            $stmt = $conn->prepare("SELECT * FROM evento WHERE id = ?");
            $stmt->bind_param("i", $eventId);
            $stmt->execute();
            $result = $stmt->get_result();

            if ($result->num_rows == 1) {
                $eventData = $result->fetch_assoc();
                echo json_encode(['event' => $eventData]);
            } else {
                http_response_code(404); // Not Found
                echo json_encode(['message' => 'Event not found']);
            }

            $stmt->close();
            $conn->close();
            exit();
        } else {
            http_response_code(400); // Bad Request
            echo json_encode(['message' => 'Event ID is required']);
            exit();
        }
    }
}


// Handle forgot password route
if ($_SERVER['REQUEST_URI'] === '/dani/index.php?endpoint=forgot_password') {
    if ($_SERVER['REQUEST_METHOD'] === 'GET') {
        include_once(__DIR__ . '/public/auth_pages/forgot_password.html');
        exit();
    } elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
        header('Content-Type: application/json'); // Set header for JSON response
        $data = json_decode(file_get_contents('php://input'), true);

        // Check if the email is provided
        if (isset($data['email'])) {
            // Connect to the database
            $conn = connectToDatabase();

            // Prepare and bind
            if ($stmt = $conn->prepare("SELECT email FROM utenti WHERE email = ?")) {
                $stmt->bind_param("s", $email);

                // Set parameter from data received
                $email = $data['email'];

                // Execute the query
                if ($stmt->execute()) {
                    $result = $stmt->get_result();
                    if ($result->num_rows == 1) {
                        // Generate a unique token for verification
                        $token = bin2hex(random_bytes(32)); // Example token generation, customize as needed

                        // Update the user record in the database with the token
                        // For example: UPDATE utenti SET reset_token = ? WHERE email = ?
                        // You'll need to add a column `reset_token` in your database table

                        // Send the verification email using PHPMailer
                        $mail = new PHPMailer(true);

                        try {
                            //Server settings
                            $mail->isSMTP();
                            $mail->Host       = 'smtp.gmail.com';
                            $mail->SMTPAuth   = true;
                            $mail->Username   = 'teacodelab@gmail.com';
                            $mail->Password   = 'boyteprmnpmutqgj'; // Use the sender's password here
                            $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
                            $mail->Port       = 587;

                            //Recipients
                            $mail->setFrom('teacodelab@gmail.com', 'TeaCodeLab');
                            $mail->addAddress($email);
                            //Content
                            $mail->isHTML(true);
                            $mail->Subject = 'Reset Your Password';
                            $mail->Body    = 'Click the following link to reset your password: http://yourwebsite.com/reset_password?token=' . $token;

                            $mail->send();
                            echo json_encode(['message' => 'Password reset instructions sent to your email']);
                            exit(); // Stop further execution
                        } catch (Exception $e) {
                            http_response_code(500); // Internal Server Error
                            echo json_encode(['message' => 'Failed to send email: ' . $mail->ErrorInfo]);
                            exit(); // Stop further execution
                        }
                    } else {
                        // No user found with the provided email
                        http_response_code(404); // Not Found
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
            // Email not provided
            http_response_code(400); // Bad Request
            echo json_encode(['message' => 'Email is required']);
            exit(); // Stop further execution
        }
    }
}


?>