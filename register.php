<?php
session_start();

// Database configuration
$db_host = 'localhost';
$db_username = 'root';
$db_password = '1953';
$db_name = 'fixly';

// Establish database connection
$conn = new mysqli($db_host, $db_username, $db_password, $db_name);

// Check database connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Handle POST request
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Get the raw POST data
    $rawData = file_get_contents("php://input");
    $data = json_decode($rawData, true);

    // Validate input
    if (isset($data['username']) && isset($data['password']) && isset($data['email'])) {
        $username = $data['username'];
        $password = $data['password'];
        $email = $data['email'];

        // Check if username or email already exists
        $stmt = $conn->prepare("SELECT username, email FROM users WHERE username = ? OR email = ?");
        $stmt->bind_param("ss", $username, $email);
        $stmt->execute();
        $stmt->store_result();
        if ($stmt->num_rows > 0) {
            $response = array('status' => 'error', 'message' => 'Username or email already exists');
        } else {
            // Hash the password
            $hashedPassword = password_hash($password, PASSWORD_BCRYPT);

            // Prepare and execute SQL statement to insert user into database
            $stmt = $conn->prepare("INSERT INTO users (username, password, email) VALUES (?, ?, ?)");
            if (!$stmt) {
                error_log("Prepare failed: " . $conn->error);
                die("Prepare failed: " . $conn->error);
            }

            $stmt->bind_param("sss", $username, $hashedPassword, $email);
            if (!$stmt->execute()) {
                error_log("Execute failed: " . $stmt->error);
                die("Execute failed: " . $stmt->error);
            }

            $response = array('status' => 'success', 'message' => 'User registered successfully');
            $stmt->close();
        }
    } else {
        // Missing username, password, or email in the request
        $response = array('status' => 'error', 'message' => 'Username, password, and email are required');
    }
} else {
    // Invalid request method
    $response = array('status' => 'error', 'message' => 'Invalid request method');
}

// Output the response in JSON format
header('Content-Type: application/json');
echo json_encode($response);

// Close database connection
$conn->close();
?>
