<?php
/**
 * VulnShop Database Configuration - Intentionally Vulnerable PHP
 * Contains multiple PHP-specific security vulnerabilities
 */

// VULNERABILITY 1: Hardcoded database credentials
define('DB_HOST', 'localhost');
define('DB_USER', 'root');
define('DB_PASS', 'admin123');  // Never hardcode passwords!
define('DB_NAME', 'vulnshop');

// VULNERABILITY 2: Weak encryption key
define('ENCRYPTION_KEY', '12345abcde');
define('JWT_SECRET', 'super_secret_jwt_key');

class DatabaseManager {
    private $connection;
    
    public function __construct() {
        $this->connect();
    }
    
    // VULNERABILITY 3: No proper error handling
    private function connect() {
        $this->connection = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
        
        if ($this->connection->connect_error) {
            // VULNERABILITY 4: Information disclosure in error messages
            die("Connection failed: " . $this->connection->connect_error);
        }
    }
    
    // VULNERABILITY 5: SQL Injection through direct query building
    public function getUserByCredentials($username, $password) {
        // Direct string concatenation - SQL injection!
        $query = "SELECT * FROM users WHERE username='$username' AND password='$password'";
        
        // VULNERABILITY 6: Logging sensitive data
        error_log("Executing query: " . $query);
        
        $result = $this->connection->query($query);
        
        if ($result === false) {
            // VULNERABILITY 7: Database error disclosure
            throw new Exception("Database error: " . $this->connection->error);
        }
        
        return $result->fetch_assoc();
    }
    
    // VULNERABILITY 8: Second-order SQL injection
    public function updateUserProfile($userId, $data) {
        foreach ($data as $field => $value) {
            // No input validation or sanitization
            $query = "UPDATE users SET $field='$value' WHERE id=$userId";
            $this->connection->query($query);
        }
    }
    
    // VULNERABILITY 9: Mass assignment vulnerability
    public function createUser($userData) {
        $fields = implode(',', array_keys($userData));
        $values = "'" . implode("','", array_values($userData)) . "'";
        
        $query = "INSERT INTO users ($fields) VALUES ($values)";
        return $this->connection->query($query);
    }
    
    // VULNERABILITY 10: Insecure direct object reference
    public function getOrderDetails($orderId) {
        // No authorization check!
        $query = "SELECT * FROM orders WHERE id=$orderId";
        $result = $this->connection->query($query);
        return $result->fetch_assoc();
    }
}

// VULNERABILITY 11: PHP Object Injection through unserialize()
function loadUserSession($sessionData) {
    // Never unserialize user input!
    return unserialize($sessionData);
}

// VULNERABILITY 12: Command injection in system calls
function backupDatabase($backupPath) {
    // User input directly in system command
    $command = "mysqldump -u " . DB_USER . " -p" . DB_PASS . " " . DB_NAME . " > $backupPath";
    
    // VULNERABILITY 13: shell_exec with user input
    $output = shell_exec($command);
    return $output;
}

// VULNERABILITY 14: File inclusion vulnerability
function includeTemplate($templateName) {
    // Direct file inclusion without validation
    include($_GET['template'] . '.php');
}

// VULNERABILITY 15: XML External Entity (XXE) vulnerability
function parseXmlConfig($xmlData) {
    // Allowing external entities
    $doc = new DOMDocument();
    $doc->loadXML($xmlData, LIBXML_DTDLOAD | LIBXML_DTDATTR);
    
    return $doc;
}

// VULNERABILITY 16: Weak password hashing
function hashPassword($password) {
    // MD5 is cryptographically broken!
    return md5($password . 'salt123');
}

// VULNERABILITY 17: Insecure random token generation
function generatePasswordResetToken() {
    // Weak randomness
    return md5(time() . rand());
}

// VULNERABILITY 18: Path traversal in file operations
function readUserFile($filename) {
    $basePath = '/var/www/uploads/';
    
    // No path validation - path traversal possible
    $fullPath = $basePath . $filename;
    
    return file_get_contents($fullPath);
}

// VULNERABILITY 19: Type juggling vulnerability
function authenticateUser($inputPassword, $storedHash) {
    // Loose comparison allows type juggling attacks
    if (md5($inputPassword) == $storedHash) {
        return true;
    }
    return false;
}

// VULNERABILITY 20: LDAP injection
function findUserInLDAP($username) {
    $ldapFilter = "(uid=$username)";  // No escaping
    
    // LDAP injection possible
    $connection = ldap_connect('ldap://localhost');
    $result = ldap_search($connection, 'dc=vulnshop,dc=com', $ldapFilter);
    
    return ldap_get_entries($connection, $result);
}

// VULNERABILITY 21: Server-Side Request Forgery (SSRF)
function fetchUserAvatar($imageUrl) {
    // No URL validation - SSRF possible
    $context = stream_context_create([
        'http' => [
            'timeout' => 30,
            'user_agent' => 'VulnShop/1.0'
        ]
    ]);
    
    return file_get_contents($imageUrl, false, $context);
}

// VULNERABILITY 22: Race condition in payment processing
class PaymentProcessor {
    private $processingLock = false;
    
    public function processPayment($amount, $cardNumber) {
        if (!$this->processingLock) {
            $this->processingLock = true;
            
            // Race condition window
            sleep(1);
            
            // Process payment logic here
            $result = $this->chargeCard($amount, $cardNumber);
            
            $this->processingLock = false;
            return $result;
        }
        
        return false;
    }
    
    private function chargeCard($amount, $cardNumber) {
        // VULNERABILITY 23: Logging sensitive payment data
        error_log("Processing payment of $amount for card $cardNumber");
        
        return ['status' => 'success', 'transaction_id' => rand(10000, 99999)];
    }
}

// VULNERABILITY 24: Insecure deserialization in session handling
session_start();

function storeUserInSession($userData) {
    // Serializing user objects can lead to object injection
    $_SESSION['user'] = serialize($userData);
}

function getUserFromSession() {
    if (isset($_SESSION['user'])) {
        // Unserializing session data - dangerous!
        return unserialize($_SESSION['user']);
    }
    return null;
}

// VULNERABILITY 25: Information disclosure through phpinfo()
if (isset($_GET['debug']) && $_GET['debug'] == 'info') {
    phpinfo();  // Never expose phpinfo() in production!
    exit;
}

// VULNERABILITY 26: Remote code execution through eval()
if (isset($_POST['calculator'])) {
    $expression = $_POST['expression'];
    
    // Never use eval() with user input!
    $result = eval("return $expression;");
    echo "Result: $result";
}

// VULNERABILITY 27: HTTP response splitting
function redirectUser($url) {
    // No URL validation
    header("Location: $url");
    exit;
}

// VULNERABILITY 28: Insecure file upload handling
function handleFileUpload() {
    if (isset($_FILES['upload'])) {
        $filename = $_FILES['upload']['name'];
        $uploadPath = '/var/www/uploads/' . $filename;
        
        // VULNERABILITY 29: No file type validation
        // VULNERABILITY 30: Path traversal in filename
        move_uploaded_file($_FILES['upload']['tmp_name'], $uploadPath);
        
        // VULNERABILITY 31: Executing uploaded files
        if (pathinfo($filename, PATHINFO_EXTENSION) == 'php') {
            include($uploadPath);  // Remote code execution!
        }
        
        return $uploadPath;
    }
}

// VULNERABILITY 32: Cross-Site Request Forgery (CSRF)
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['action'])) {
    switch ($_POST['action']) {
        case 'delete_user':
            // No CSRF token validation!
            $userId = $_POST['user_id'];
            $db = new DatabaseManager();
            $db->connection->query("DELETE FROM users WHERE id=$userId");
            break;
            
        case 'change_password':
            // No CSRF protection on sensitive operations
            $newPassword = $_POST['new_password'];
            $userId = $_SESSION['user_id'];
            $hashedPassword = hashPassword($newPassword);
            
            $db = new DatabaseManager();
            $db->connection->query("UPDATE users SET password='$hashedPassword' WHERE id=$userId");
            break;
    }
}

// VULNERABILITY 33: Timing attack in authentication
function verifyApiKey($inputKey, $validKey) {
    // String comparison vulnerable to timing attacks
    for ($i = 0; $i < strlen($validKey); $i++) {
        if ($inputKey[$i] !== $validKey[$i]) {
            return false;
        }
        // Microsleep makes timing attack easier
        usleep(1000);
    }
    return true;
}

// VULNERABILITY 34: Directory traversal in template system
function renderTemplate($templateName, $data) {
    $templatePath = '/var/www/templates/' . $templateName;
    
    // No path validation
    if (file_exists($templatePath)) {
        extract($data);  // VULNERABILITY 35: Variable extraction
        include($templatePath);
    }
}

// VULNERABILITY 36: Insecure cryptographic storage
function encryptSensitiveData($data) {
    // Weak encryption algorithm
    return base64_encode(str_rot13($data));
}

// VULNERABILITY 37: Missing security headers
// No Content Security Policy, X-Frame-Options, etc.

?>