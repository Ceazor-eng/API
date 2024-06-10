<?php
session_start();

// Include the JWT library
require __DIR__ . '/vendor/autoload.php'; // Adjust the path as per your project structure

use Firebase\JWT\JWT;

// Define your JWT secret key (keep it secure and unique)
define('JWT_SECRET', 'G+uOcLDhvAHzqFkaHW04nKBBRKitN/xYNAwuTtNHHSM=');

// Function to generate JWT token
function generateJWT($username, $jwt_secret) {
    $payload = array(
        "username" => $username,
        "iat" => time(),
        "exp" => time() + (60 * 60) // Token expiration time (1 hour)
    );

    $token = JWT::encode($payload, $jwt_secret, 'HS256');


    // Log JWT information
    // error_log("Generated JWT for user: $username, Token: $token");

    return $token;
}



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

// Handle POST request for user login
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Get the raw POST data
    $rawData = file_get_contents("php://input");
    $data = json_decode($rawData, true);

    // Validate input
    if (isset($data['username']) && isset($data['password'])) {
        $username = $data['username'];
        $password = $data['password'];

        // Fetch user from the database based on username
        $stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows > 0) {
            $user = $result->fetch_assoc();
            // Verify password
            if (password_verify($password, $user['password'])) {
                // Password is correct, generate JWT token
                $token = generateJWT($username, JWT_SECRET);

                // Split the token and ignore index 0
              // Split the token and ignore index 0
                    //  $tokenParts = str_split($token);
                    //  $accessToken = $tokenParts;

                     // Log the access token
                        error_log($token);


                // User logged in successfully
                $response = array('status' => 'success', 'message' => 'User logged in successfully', 'token' => $token);
            } else {
                // Incorrect password
                $response = array('status' => 'error', 'message' => 'Incorrect password');
            }
        } else {
            // User not found
            $response = array('status' => 'error', 'message' => 'User not found');
        }
        $stmt->close();
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
