// Toggle the registration form visibility
function toggleRegisterForm() {
    const registerForm = document.getElementById("registerForm");
    registerForm.style.display = registerForm.style.display === "none" ? "block" : "none";
}

// Load logs from the database on page load
window.addEventListener("load", async () => {
    try {
        const response = await fetch("/api/logs"); // Fetch logs from the database
        const logs = await response.json();
        logs.forEach(log => addLog(log.message));
    } catch (error) {
        console.error("Error loading logs:", error);
    }
});

// Handle form submission for registering a new user
async function registerUser(event) {
    event.preventDefault(); // Prevent the default form submission

    // Get form values
    const username = document.getElementById("username").value;
    const email = document.getElementById("email").value;
    const password = document.getElementById("password").value;

    // Validate form fields
    if (!username || !email || !password) {
        alert("All fields are required.");
        return;
    }

    try {
        // Send user data to the server to register the user
        const response = await fetch("/api/register", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, email, password }),
        });

        const result = await response.json();

        if (response.ok) {
            // Notify the user and add a log entry
            alert(`User ${result.username} registered successfully!`);
            addLog(`New user registered: ${result.username}, Email: ${result.email}`);
            
            // Clear form and hide it after submission
            document.querySelector("form").reset();
            toggleRegisterForm();
        } else {
            // Handle errors (e.g., duplicate email)
            alert(result.message || "An error occurred while registering the user.");
        }
    } catch (error) {
        console.error("Error registering user:", error);
        alert("Failed to register user. Please try again.");
    }
}

// Function to add a log entry to the logs section
function addLog(message) {
    const logsContainer = document.getElementById("logs");

    // Create a new log entry element
    const logEntry = document.createElement("div");
    logEntry.classList.add("log-entry");
    logEntry.textContent = message;

    // Append the new log entry to the logs container
    logsContainer.appendChild(logEntry);
}

