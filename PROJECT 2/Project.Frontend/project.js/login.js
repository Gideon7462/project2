document.getElementById("loginForm").addEventListener("submit", loginUser);

async function loginUser(event) {
    event.preventDefault(); // Prevent form from refreshing the page

    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;
    const errorMessage = document.getElementById("errorMessage");

    try {
        const response = await fetch("http://localhost:5000/api/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, password }),
        });

        const data = await response.json();
        if (response.ok) {
            alert(`Welcome, ${username}! You have successfully logged in.`);
            localStorage.setItem("token", data.token); // Store the JWT token
            window.location.href = "dashboard.html"; // Redirect to the dashboard
        } else {
            errorMessage.textContent = data.error || "Login failed. Please try again.";
        }
    } catch (error) {
        console.error("Login error:", error);
        errorMessage.textContent = "Server error. Please try again later.";
    }

    // Clear the form after submission
    document.getElementById("loginForm").reset();
}
