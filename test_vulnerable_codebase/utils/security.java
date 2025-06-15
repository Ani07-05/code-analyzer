/**
 * VulnShop Security Utilities - Intentionally Vulnerable Java Code
 * Contains multiple Java-specific security vulnerabilities
 * 
 * WARNING: This code is intentionally insecure for testing purposes!
 */

package com.vulnshop.utils;

import java.io.*;
import java.net.*;
import java.sql.*;
import java.util.*;
import java.security.*;
import javax.crypto.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.util.regex.*;
import javax.xml.parsers.*;
import org.w3c.dom.*;
import java.lang.reflect.*;

public class SecurityUtils {
    
    // VULNERABILITY 1: Hardcoded credentials
    private static final String DB_PASSWORD = "admin123";
    private static final String API_SECRET = "super_secret_api_key_2023";
    private static final String ENCRYPTION_KEY = "1234567890abcdef";
    
    // VULNERABILITY 2: Weak random number generation
    private static final Random random = new Random(12345); // Fixed seed!
    
    /**
     * VULNERABILITY 3: SQL Injection through string concatenation
     */
    public static User authenticateUser(String username, String password) throws SQLException {
        Connection conn = DriverManager.getConnection(
            "jdbc:mysql://localhost/vulnshop", "root", DB_PASSWORD);
        
        // Direct string concatenation - SQL injection!
        String query = "SELECT * FROM users WHERE username='" + username + 
                      "' AND password='" + password + "'";
        
        // VULNERABILITY 4: Logging sensitive data
        System.out.println("Executing query: " + query);
        
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(query);
        
        if (rs.next()) {
            return new User(rs.getString("username"), rs.getString("email"));
        }
        
        return null;
    }
    
    /**
     * VULNERABILITY 5: Deserialization of untrusted data
     */
    public static Object deserializeUserData(byte[] data) {
        try {
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
            // Never deserialize untrusted data!
            return ois.readObject();
        } catch (Exception e) {
            // VULNERABILITY 6: Information disclosure in error messages
            throw new RuntimeException("Deserialization failed: " + e.getMessage(), e);
        }
    }
    
    /**
     * VULNERABILITY 7: Command injection
     */
    public static String executeSystemCommand(String userInput) {
        try {
            // Direct execution of user input
            String command = "ping -c 1 " + userInput;
            
            Process process = Runtime.getRuntime().exec(command);
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            
            // VULNERABILITY 8: Command output disclosure
            return output.toString();
            
        } catch (Exception e) {
            return "Command execution failed: " + e.getMessage();
        }
    }
    
    /**
     * VULNERABILITY 9: Path traversal in file operations
     */
    public static String readUserFile(String filename) {
        try {
            String basePath = "/var/www/uploads/";
            
            // No path validation - path traversal possible
            File file = new File(basePath + filename);
            
            BufferedReader reader = new BufferedReader(new FileReader(file));
            StringBuilder content = new StringBuilder();
            String line;
            
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\n");
            }
            
            reader.close();
            return content.toString();
            
        } catch (Exception e) {
            // VULNERABILITY 10: File system information disclosure
            return "File read error: " + e.getMessage() + " - Path: " + filename;
        }
    }
    
    /**
     * VULNERABILITY 11: XML External Entity (XXE) injection
     */
    public static Document parseXmlConfig(String xmlData) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            
            // XXE vulnerability - external entities enabled
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", true);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", true);
            
            DocumentBuilder builder = factory.newDocumentBuilder();
            return builder.parse(new ByteArrayInputStream(xmlData.getBytes()));
            
        } catch (Exception e) {
            throw new RuntimeException("XML parsing failed: " + e.getMessage());
        }
    }
    
    /**
     * VULNERABILITY 12: Weak cryptographic implementation
     */
    public static String encryptData(String data) {
        try {
            // Weak encryption algorithm (DES)
            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            
            // Hardcoded key
            byte[] keyBytes = ENCRYPTION_KEY.substring(0, 8).getBytes();
            SecretKeySpec key = new SecretKeySpec(keyBytes, "DES");
            
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encrypted = cipher.doFinal(data.getBytes());
            
            return Base64.getEncoder().encodeToString(encrypted);
            
        } catch (Exception e) {
            throw new RuntimeException("Encryption failed: " + e.getMessage());
        }
    }
    
    /**
     * VULNERABILITY 13: Insecure random token generation
     */
    public static String generateSessionToken() {
        // Predictable random generation
        return String.valueOf(random.nextLong());
    }
    
    /**
     * VULNERABILITY 14: LDAP injection
     */
    public static List<String> findUsersInDirectory(String searchTerm) {
        try {
            // Direct string concatenation in LDAP filter
            String filter = "(cn=" + searchTerm + ")";
            
            // LDAP injection possible
            Hashtable<String, String> env = new Hashtable<>();
            env.put("java.naming.factory.initial", "com.sun.jndi.ldap.LdapCtxFactory");
            env.put("java.naming.provider.url", "ldap://localhost:389");
            
            javax.naming.directory.DirContext ctx = 
                new javax.naming.directory.InitialDirContext(env);
            
            // Vulnerable LDAP search
            javax.naming.directory.SearchControls controls = 
                new javax.naming.directory.SearchControls();
            
            javax.naming.NamingEnumeration<?> results = 
                ctx.search("dc=vulnshop,dc=com", filter, controls);
            
            List<String> users = new ArrayList<>();
            while (results.hasMore()) {
                javax.naming.directory.SearchResult result = 
                    (javax.naming.directory.SearchResult) results.next();
                users.add(result.getName());
            }
            
            return users;
            
        } catch (Exception e) {
            throw new RuntimeException("LDAP search failed: " + e.getMessage());
        }
    }
    
    /**
     * VULNERABILITY 15: Server-Side Request Forgery (SSRF)
     */
    public static String fetchExternalResource(String url) {
        try {
            // No URL validation - SSRF possible
            URL resourceUrl = new URL(url);
            URLConnection connection = resourceUrl.openConnection();
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(connection.getInputStream()));
            
            StringBuilder content = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\n");
            }
            
            return content.toString();
            
        } catch (Exception e) {
            return "SSRF attempt failed: " + e.getMessage();
        }
    }
    
    /**
     * VULNERABILITY 16: Code injection through reflection
     */
    public static Object invokeUserMethod(String className, String methodName, Object[] args) {
        try {
            // Dynamic class loading - code injection possible
            Class<?> clazz = Class.forName(className);
            Object instance = clazz.newInstance();
            
            // Dynamic method invocation
            Method method = clazz.getMethod(methodName, getParameterTypes(args));
            return method.invoke(instance, args);
            
        } catch (Exception e) {
            throw new RuntimeException("Method invocation failed: " + e.getMessage());
        }
    }
    
    private static Class<?>[] getParameterTypes(Object[] args) {
        Class<?>[] types = new Class<?>[args.length];
        for (int i = 0; i < args.length; i++) {
            types[i] = args[i].getClass();
        }
        return types;
    }
    
    /**
     * VULNERABILITY 17: Race condition in critical section
     */
    private static int accountBalance = 1000;
    private static boolean transactionInProgress = false;
    
    public static synchronized boolean withdrawMoney(int amount) {
        if (!transactionInProgress && accountBalance >= amount) {
            transactionInProgress = true;
            
            // Race condition window
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            
            accountBalance -= amount;
            transactionInProgress = false;
            
            // VULNERABILITY 18: Information disclosure
            System.out.println("Withdrawal successful. New balance: " + accountBalance);
            return true;
        }
        
        return false;
    }
    
    /**
     * VULNERABILITY 19: Weak input validation
     */
    public static boolean isValidEmail(String email) {
        // Weak regex that can be bypassed
        return email.contains("@") && email.contains(".");
    }
    
    /**
     * VULNERABILITY 20: Information disclosure through stack traces
     */
    public static void processPayment(String cardNumber, String cvv, double amount) {
        try {
            if (cardNumber.length() < 13) {
                throw new IllegalArgumentException("Invalid card number: " + cardNumber);
            }
            
            if (cvv.length() != 3) {
                throw new IllegalArgumentException("Invalid CVV: " + cvv);
            }
            
            // Payment processing logic...
            chargeCard(cardNumber, amount);
            
        } catch (Exception e) {
            // VULNERABILITY 21: Full exception disclosure
            e.printStackTrace();
            throw new RuntimeException("Payment processing failed with card " + cardNumber, e);
        }
    }
    
    private static void chargeCard(String cardNumber, double amount) throws Exception {
        // VULNERABILITY 22: Logging sensitive financial data
        System.out.println("Charging card " + cardNumber + " for $" + amount);
        
        // Simulate payment processing
        if (random.nextBoolean()) {
            throw new Exception("Payment gateway error: Card declined");
        }
    }
    
    /**
     * VULNERABILITY 23: Unsafe file upload handling
     */
    public static String handleFileUpload(HttpServletRequest request) {
        try {
            String uploadDir = "/var/www/uploads/";
            String filename = request.getParameter("filename");
            
            // VULNERABILITY 24: Path traversal in filename
            File uploadFile = new File(uploadDir + filename);
            
            // VULNERABILITY 25: No file type validation
            // VULNERABILITY 26: Executable file upload allowed
            
            // Create the file
            uploadFile.createNewFile();
            
            return "File uploaded: " + uploadFile.getAbsolutePath();
            
        } catch (Exception e) {
            return "Upload failed: " + e.getMessage();
        }
    }
    
    /**
     * VULNERABILITY 27: Timing attack vulnerability
     */
    public static boolean validateApiKey(String inputKey) {
        String validKey = API_SECRET;
        
        // Vulnerable to timing attacks
        for (int i = 0; i < validKey.length(); i++) {
            if (i >= inputKey.length() || inputKey.charAt(i) != validKey.charAt(i)) {
                return false;
            }
            
            // Artificial delay makes timing attack easier
            try {
                Thread.sleep(1);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
        
        return inputKey.length() == validKey.length();
    }
    
    /**
     * VULNERABILITY 28: Expression Language injection
     */
    public static String evaluateExpression(String expression) {
        try {
            // EL injection vulnerability
            javax.el.ExpressionFactory factory = 
                javax.el.ExpressionFactory.newInstance();
            
            javax.el.StandardELContext context = new javax.el.StandardELContext(factory);
            
            javax.el.ValueExpression valueExpression = 
                factory.createValueExpression(context, expression, String.class);
            
            return (String) valueExpression.getValue(context);
            
        } catch (Exception e) {
            return "Expression evaluation failed: " + e.getMessage();
        }
    }
    
    /**
     * VULNERABILITY 29: Weak password hashing
     */
    public static String hashPassword(String password) {
        try {
            // MD5 is cryptographically broken!
            MessageDigest md = MessageDigest.getInstance("MD5");
            
            // No salt used
            byte[] hash = md.digest(password.getBytes());
            
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            
            return hexString.toString();
            
        } catch (Exception e) {
            throw new RuntimeException("Password hashing failed: " + e.getMessage());
        }
    }
    
    /**
     * VULNERABILITY 30: Trust boundary violation
     */
    public static void processUserInput(String userInput, HttpServletResponse response) {
        try {
            // Direct output of user input - XSS vulnerability
            PrintWriter out = response.getWriter();
            out.println("<html><body>");
            out.println("<h1>User Input: " + userInput + "</h1>");
            out.println("</body></html>");
            
        } catch (Exception e) {
            throw new RuntimeException("Output failed: " + e.getMessage());
        }
    }
}

/**
 * Simple User class for demonstration
 */
class User implements Serializable {
    private String username;
    private String email;
    
    public User(String username, String email) {
        this.username = username;
        this.email = email;
    }
    
    // Getters and setters...
    public String getUsername() { return username; }
    public String getEmail() { return email; }
}