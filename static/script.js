document.getElementById("login-form").addEventListener("submit", async (event) => {
    event.preventDefault();

    const username = document.getElementById("username").value.trim();
    const password = document.getElementById("password").value.trim();
    const messageBox = document.getElementById("message");

    if (!username || !password) {
        messageBox.innerText = "Username and password are required!";
        return;
    }

    const formData = new FormData();
    formData.append("username", username);
    formData.append("password", password);

    const response = await fetch("/login", {
        method: "POST",
        body: formData
    });

    const data = await response.json();
    if (response.ok) {
        messageBox.style.color = "green";
        messageBox.innerText = "Login successful! Redirecting...";
        localStorage.setItem("access_token", data.access_token); // Сохраняем токен
        setTimeout(() => { window.location.href = "/"; }, 2000);
    } else {
        messageBox.style.color = "red";
        messageBox.innerText = data.detail;
    }
});