/*
 * Post form to Codehooks server.
 */
function passwordSignIn(event) {
    event.preventDefault();
    
    const data = {
        username: document.getElementById('username').value,
        password: document.getElementById('password').value
    };
    
    fetch('/dev/auth/login', {
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
        if (response.redirected) {
            window.location.href = response.url;
        }
        //return response.json();
    })
    /*.then(data => {
        if (data.token) {
            localStorage.setItem('jwtToken', data.token);
            //window.location.href = 'dashboard.html';
            console.log('Status:', data);
        }
    })*/
    .catch((error) => {
        console.error('Error:', error);
        document.getElementById('error-message').style.display = 'block';
    });
}

// Execute the function when the page loads
/*
window.onload = function() {
    console.log('Password form onload')
    document.getElementById('login-form').addEventListener('submit', passwordSignIn);
};
*/
document.addEventListener('DOMContentLoaded', function() {
    console.log("Password: DOM fully loaded and parsed");
    // Your event listener code here
    document.getElementById('login-form').addEventListener('submit', passwordSignIn);
});