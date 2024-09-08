/*
 * Post form to Codehooks server.
 */
function passwordSignIn(event) {
    event.preventDefault();
    
    const data = {
        username: document.getElementById('username').value,
        password: document.getElementById('password').value
    };
    
    fetch('/auth/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
    })
    .then(response => {
        if (response.status > 201) {
            document.getElementById('error-message').style.display = 'block';
        } else {
            document.getElementById('error-message').style.display = 'none';                    
        }
       
        return response.json();
    })
    .then(data => {
        if (data.access_token) {
            console.log('Status:', data);
            localStorage.setItem('access_token', data.access_token);
            window.location.href = data.redirectURL;
            
        } else {
            console.error('No access token from server')
        }
    })
    .catch((error) => {
        console.error('Error:', error);
        document.getElementById('error-message').style.display = 'block';
    });
}

// Execute the function when the page loads
document.addEventListener('DOMContentLoaded', function() {
    console.log("Password: DOM fully loaded and parsed");
    // Your event listener code here
    document.getElementById('login-form').addEventListener('submit', passwordSignIn);
});