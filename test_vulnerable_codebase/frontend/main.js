/**
 * VulnShop Frontend - Intentionally Vulnerable JavaScript
 * Contains multiple client-side security vulnerabilities
 */

// VULNERABILITY 1: Hardcoded API credentials
const API_BASE_URL = 'http://localhost:5000/api';
const API_KEY = 'api_key_admin_2023';  // Never hardcode API keys!
const ADMIN_TOKEN = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.abc123';

// VULNERABILITY 2: Sensitive data in localStorage
function storeUserData(userData) {
    // Never store sensitive data in localStorage!
    localStorage.setItem('user_data', JSON.stringify(userData));
    localStorage.setItem('credit_card', userData.creditCard);
    localStorage.setItem('ssn', userData.ssn);
    localStorage.setItem('api_key', API_KEY);
}

// VULNERABILITY 3: DOM-based XSS
function displayWelcomeMessage() {
    const urlParams = new URLSearchParams(window.location.search);
    const username = urlParams.get('username');
    
    if (username) {
        // Direct DOM manipulation without sanitization
        document.getElementById('welcome').innerHTML = `Welcome back, ${username}!`;
        document.title = `VulnShop - ${username}'s Dashboard`;
    }
}

// VULNERABILITY 4: Client-side authentication bypass
function checkAdminAccess() {
    const userRole = localStorage.getItem('user_role');
    
    // Client-side role checking is never secure!
    if (userRole === 'admin') {
        document.getElementById('admin-panel').style.display = 'block';
        return true;
    }
    return false;
}

// VULNERABILITY 5: Insecure cryptographic implementation
function hashPassword(password) {
    // MD5 is cryptographically broken!
    return btoa(password).split('').reverse().join('');  // Weak custom "encryption"
}

// VULNERABILITY 6: CSRF vulnerability - missing CSRF tokens
function makePayment(amount, cardNumber, cvv) {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', `${API_BASE_URL}/process_payment`, true);
    xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    
    // No CSRF token included!
    const data = `amount=${amount}&card_number=${cardNumber}&cvv=${cvv}`;
    
    xhr.onreadystatechange = function() {
        if (xhr.readyState === 4) {
            if (xhr.status === 200) {
                const response = JSON.parse(xhr.responseText);
                // VULNERABILITY 7: Logging sensitive data to console
                console.log('Payment response:', response);
                console.log('Card details:', cardNumber, cvv);
                
                displayPaymentResult(response);
            } else {
                console.error('Payment failed:', xhr.responseText);
            }
        }
    };
    
    xhr.send(data);
}

// VULNERABILITY 8: Eval() usage - Code injection
function processUserScript(userInput) {
    try {
        // Never use eval() with user input!
        const result = eval(userInput);
        document.getElementById('script-result').innerHTML = result;
    } catch (error) {
        console.error('Script execution error:', error);
    }
}

// VULNERABILITY 9: Insecure direct object references
function loadUserProfile(userId) {
    // No authorization check on client side
    fetch(`${API_BASE_URL}/user_data/${userId}`, {
        headers: {
            'X-API-Key': API_KEY
        }
    })
    .then(response => response.json())
    .then(data => {
        // VULNERABILITY 10: Exposing sensitive data in DOM
        document.getElementById('profile-data').innerHTML = `
            <h3>User Profile</h3>
            <p>Username: ${data.username}</p>
            <p>Email: ${data.email}</p>
            <p>Credit Card: ${data.credit_card}</p>
            <p>SSN: ${data.ssn}</p>
            <p>Password Hash: ${data.password_hash}</p>
        `;
    })
    .catch(error => console.error('Error:', error));
}

// VULNERABILITY 11: Prototype pollution
function updateConfig(userConfig) {
    const config = {};
    
    // Prototype pollution vulnerability
    for (let key in userConfig) {
        config[key] = userConfig[key];
    }
    
    return config;
}

// VULNERABILITY 12: Insecure randomness
function generateSessionId() {
    // Math.random() is not cryptographically secure!
    return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
}

// VULNERABILITY 13: Client-side SQL injection (if backend is vulnerable)
function searchProducts(searchTerm, category) {
    // Building query on client side - can be manipulated
    const query = `SELECT * FROM products WHERE name LIKE '%${searchTerm}%' AND category='${category}'`;
    
    fetch(`${API_BASE_URL}/search`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-API-Key': API_KEY
        },
        body: JSON.stringify({ query: query })
    })
    .then(response => response.json())
    .then(data => displaySearchResults(data))
    .catch(error => console.error('Search error:', error));
}

// VULNERABILITY 14: Unsafe innerHTML usage
function displaySearchResults(results) {
    let html = '<h3>Search Results</h3>';
    
    results.forEach(result => {
        // Direct innerHTML injection - XSS risk
        html += `<div class="product">
            <h4>${result.name}</h4>
            <p>${result.description}</p>
            <p>Price: $${result.price}</p>
        </div>`;
    });
    
    document.getElementById('results').innerHTML = html;
}

// VULNERABILITY 15: Insecure HTTP requests (no HTTPS)
function syncUserData() {
    const userData = localStorage.getItem('user_data');
    
    // Sending sensitive data over HTTP
    fetch('http://api.vulnshop.com/sync', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${ADMIN_TOKEN}`
        },
        body: userData
    })
    .then(response => response.json())
    .then(data => console.log('Sync complete:', data))
    .catch(error => console.error('Sync error:', error));
}

// VULNERABILITY 16: Click-jacking vulnerability (missing frame-busting)
// No protection against embedding in malicious iframes

// VULNERABILITY 17: Weak input validation
function validateCreditCard(cardNumber) {
    // Weak client-side validation only
    return cardNumber.length >= 13;  // Not a real validation!
}

// VULNERABILITY 18: Information disclosure in error messages
function handleApiError(error) {
    const errorDiv = document.getElementById('error-messages');
    
    // Displaying full error details to user
    errorDiv.innerHTML = `
        <div class="error">
            <h4>Error Details:</h4>
            <p>Message: ${error.message}</p>
            <p>Stack: ${error.stack}</p>
            <p>API Endpoint: ${error.url}</p>
            <p>Request Data: ${JSON.stringify(error.requestData)}</p>
        </div>
    `;
}

// VULNERABILITY 19: Race condition in payment processing
let paymentInProgress = false;

function processPaymentRace(amount) {
    if (!paymentInProgress) {
        paymentInProgress = true;
        
        // Race condition window
        setTimeout(() => {
            makePayment(amount, '4111111111111111', '123');
            paymentInProgress = false;
        }, 100);
    }
}

// VULNERABILITY 20: Insecure WebSocket usage
function connectToChat() {
    // No authentication or validation
    const ws = new WebSocket('ws://localhost:8080/chat');
    
    ws.onmessage = function(event) {
        // Direct DOM injection without sanitization
        document.getElementById('chat-messages').innerHTML += `<div>${event.data}</div>`;
    };
    
    // VULNERABILITY 21: Automatic reconnection without rate limiting
    ws.onclose = function() {
        setTimeout(connectToChat, 1000);  // Immediate reconnection
    };
}

// Initialize vulnerable functions when page loads
document.addEventListener('DOMContentLoaded', function() {
    displayWelcomeMessage();
    checkAdminAccess();
    
    // VULNERABILITY 22: Automatic execution of potentially dangerous functions
    const autoExecute = localStorage.getItem('auto_execute');
    if (autoExecute) {
        processUserScript(autoExecute);
    }
});

// VULNERABILITY 23: Global variables exposing sensitive data
window.vulnerableGlobals = {
    apiKey: API_KEY,
    adminToken: ADMIN_TOKEN,
    databaseConfig: {
        host: 'localhost',
        username: 'admin',
        password: 'admin123'
    }
};