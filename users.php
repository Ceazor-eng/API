<?php
session_start();

require __DIR__ . '/vendor/autoload.php'; 

use Firebase\JWT\JWT;

define('JWT_SECRET', 'G+uOcLDhvAHzqFkaHW04nKBBRKitN/xYNAwuTtNHHSM=');

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

// Function to verify JWT token
function verifyJWT($token) {
    try {
        $decoded = JWT::decode($token, JWT_SECRET, );
        return (array) $decoded;
    } catch (Exception $e) {
        return false;
    }
}


// Handle GET request
if ($_SERVER['REQUEST_METHOD'] == 'GET') {
    // Get all request headers
    $headers = getallheaders();
    
    if (isset($headers['Authorization'])) {
        $authHeader = $headers['Authorization'];
        // Extract the JWT token
        list(, $jwt) = explode(' ', $authHeader);

        if ($jwt) {
            $decoded = verifyJWT($jwt);
            if ($decoded) {
                $username = $decoded['username'];

                // Fetch user information from database
                $stmt = $conn->prepare("SELECT username, email FROM users WHERE username = ?");
                $stmt->bind_param("s", $username);
                $stmt->execute();
                $result = $stmt->get_result();
                $user = $result->fetch_assoc();

                if ($user) {
                    $response = array('status' => 'success', 'user' => $user);
                } else {
                    $response = array('status' => 'error', 'message' => 'User not found');
                }
                $stmt->close();
            } else {
                $response = array('status' => 'error', 'message' => 'Invalid token');
            }
        } else {
            $response = array('status' => 'error', 'message' => 'Bearer token not provided');
        }
    } else {
        $response = array('status' => 'error', 'message' => 'Authorization header not found');
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
