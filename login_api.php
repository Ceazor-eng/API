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

// Function to generate a simple auth token
function generateAuthToken() {
    return bin2hex(random_bytes(16)); // Generates a random token
}

// Handle POST request for user login
if ($_SERVER['REQUEST_METHOD'] == 'POST' && strpos($_SERVER['REQUEST_URI'], '/login') !== false) {
    // Get the raw POST data
    $rawData = file_get_contents("php://input");
    $data = json_decode($rawData, true);

    // Log the received data for debugging
    error_log("Received data: " . print_r($data, true));

    // Validate input
    if (isset($data['username']) && isset($data['password'])) {
        $username = $data['username'];
        $password = $data['password'];

        // Prepare and execute SQL statement to fetch user from database
        $stmt = $conn->prepare("SELECT id, password, created_at, status, auth_token FROM users WHERE username = ?");
        if (!$stmt) {
            error_log("Prepare failed: " . $conn->error);
            die("Prepare failed: " . $conn->error);
        }

        $stmt->bind_param("s", $username);
        if (!$stmt->execute()) {
            error_log("Execute failed: " . $stmt->error);
            die("Execute failed: " . $stmt->error);
        }

        $result = $stmt->get_result();
        if ($result->num_rows > 0) {
            // User found, check password
            $user = $result->fetch_assoc();
            if (password_verify($password, $user['password'])) {
                // Passwords match, generate new auth token
                $authToken = generateAuthToken();

                // Update auth token in the database
                $stmt->close(); // Close the first statement here

                $update_stmt = $conn->prepare("UPDATE users SET auth_token = ? WHERE id = ?");
                if (!$update_stmt) {
                    error_log("Prepare failed: " . $conn->error);
                    die("Prepare failed: " . $conn->error);
                }

                $update_stmt->bind_param("si", $authToken, $user['id']);
                if (!$update_stmt->execute()) {
                    error_log("Execute failed: " . $update_stmt->error);
                    die("Execute failed: " . $update_stmt->error);
                }

                $update_stmt->close(); // Close the update statement

                // Return success message with auth token, created_at, and status
                $response = array(
                    'status' => 'success',
                    'message' => 'Login successful',
                    'auth_token' => $authToken,
                    'created_at' => $user['created_at'],
                    'user_status' => $user['status']
                );
            } else {
                // Passwords don't match
                $response = array('status' => 'error', 'message' => 'Invalid password');
            }
        } else {
            // User not found
            $response = array('status' => 'error', 'message' => 'Username not found');
        }

    } else {
        // Missing username or password in the request
        $response = array('status' => 'error', 'message' => 'Username and password are required');
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

