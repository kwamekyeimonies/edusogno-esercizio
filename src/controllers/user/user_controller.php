class AuthController {
public function handleSignup($postData) {
// Validate form input
$name = $postData['name'];
$surname = $postData['surname'];
$email = $postData['email'];
$password = $postData['password'];

// Example validation, you can add more checks as needed
if (empty($name) || empty($surname) || empty($email) || empty($password)) {
// Handle validation error, e.g., redirect back to the signup page with an error message
header("Location: /signup.html?error=empty_fields");
exit();
}

// Perform database transaction
// Example using PDO
$pdo = new PDO("mysql:host=localhost;dbname=mydatabase", "username", "password");
$stmt = $pdo->prepare("INSERT INTO users (name, surname, email, password) VALUES (?, ?, ?, ?)");
$stmt->execute([$name, $surname, $email, $password]);

// Redirect the user after successful signup
header("Location: /welcome.php");
exit();
}
}