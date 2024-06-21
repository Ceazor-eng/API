<?php
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

// Handle POST request for user registration
if ($_SERVER['REQUEST_METHOD'] == 'POST' && strpos($_SERVER['REQUEST_URI'], '/register') !== false) {
    // Get the raw POST data
    $rawData = file_get_contents("php://input");
    $data = json_decode($rawData, true);

    // Validate input
    if (isset($data['username']) && isset($data['password']) && isset($data['email'])) {
        $username = $data['username'];
        $password = $data['password'];
        $email = $data['email'];

        // Hash the password
        $hashedPassword = password_hash($password, PASSWORD_BCRYPT);
        
        // Generate auth token
        $authToken = generateAuthToken();

        // Prepare and execute SQL statement to insert user into database
        $stmt = $conn->prepare("INSERT INTO users (username, password, email, auth_token, created_at, status) VALUES (?, ?, ?, ?, NOW(), 'active')");
        if (!$stmt) {
            error_log("Prepare failed: " . $conn->error);
            die("Prepare failed: " . $conn->error);
        }

        $stmt->bind_param("ssss", $username, $hashedPassword, $email, $authToken);
        if (!$stmt->execute()) {
            error_log("Execute failed: " . $stmt->error);
            die("Execute failed: " . $stmt->error);
        }

        // Fetch the created_at timestamp for the new user
        $userId = $stmt->insert_id;
        $stmt->close();

        $stmt = $conn->prepare("SELECT created_at FROM users WHERE id = ?");
        if (!$stmt) {
            error_log("Prepare failed: " . $conn->error);
            die("Prepare failed: " . $conn->error);
        }

        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $stmt->bind_result($createdAt);
        $stmt->fetch();

        $response = array(
            'status' => '1',
            'message' => 'User registered successfully',
            'auth_token' => $authToken,
            'created_at' => $createdAt
        );
        $stmt->close();
    } else {
        // Missing username, password, or email in the request
        $response = array('status' => 'error', 'message' => 'Username, password, and email are required');
    }

    // Output the response in JSON format
    header('Content-Type: application/json');
    echo json_encode($response);

    // Close database connection
    $conn->close();
    exit;
}

// Handle GET request for a protected endpoint
if ($_SERVER['REQUEST_METHOD'] == 'GET' && strpos($_SERVER['REQUEST_URI'], '/protected') !== false) {
    $headers = getallheaders(); // Use apache_request_headers() if getallheaders() is unavailable
    if (isset($headers['Authorization'])) {
        $authHeader = $headers['Authorization'];
        list($authToken) = sscanf($authHeader, 'Bearer %s');

        if ($authToken) {
            // Validate token against database
            $stmt = $conn->prepare("SELECT * FROM users WHERE auth_token = ?");
            if (!$stmt) {
                error_log("Prepare failed: " . $conn->error);
                die("Prepare failed: " . $conn->error);
            }

            $stmt->bind_param("s", $authToken);
            $stmt->execute();
            $result = $stmt->get_result();

            if ($result->num_rows > 0) {
                // Token is valid
                $response = array('status' => '1', 'data' => 'Protected data');
            } else {
                // Token is invalid
                http_response_code(401);
                $response = array('status' => '3', 'message' => 'Invalid token');
            }

            $stmt->close();
        } else {
            // No token provided
            http_response_code(400);
            $response = array('status' => '4', 'message' => 'Token not provided');
        }
    } else {
        // No Authorization header
        http_response_code(400);
        $response = array('status' => '5', 'message' => 'Authorization header not found');
    }

    // Output the response in JSON format
    header('Content-Type: application/json');
    echo json_encode($response);

    // Close database connection
    $conn->close();
    exit;
}

// Invalid request method
http_response_code(405);
$response = array('status' => 'error', 'message' => 'Invalid request method');

// Output the response in JSON format
header('Content-Type: application/json');
echo json_encode($response);

// Close database connection
$conn->close();

