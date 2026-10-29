const API_BASE = "http://localhost:3000";

function fillDemoLogin(user, pass) {
    const u = document.getElementById("username");
    const p = document.getElementById("password");
    if (u && p) {
        u.value = user;
        p.value = pass;
        u.focus();
    }
}

const loginForm = document.getElementById("loginForm");

if (loginForm) {
    loginForm.addEventListener("submit", function(event) {
        event.preventDefault();

        const usernameInput = document.getElementById("username");
        const passwordInput = document.getElementById("password");
        const messageEl = document.getElementById("message");
        const loginBtn = document.getElementById("loginButton");

        const username = usernameInput ? usernameInput.value.trim() : "";
        const password = passwordInput ? passwordInput.value : "";

        if (!username || !password) {
            if (messageEl) {
                messageEl.className = "";
                messageEl.textContent = "Please enter both username and password.";
            }
            return;
        }

        if (loginBtn) {
            loginBtn.disabled = true;
            loginBtn.textContent = "Signing in...";
        }

        fetch(`${API_BASE}/login`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                username: username,
                password: password
            })
        })
        .then(async response => {
            const data = await response.json();
            return { ok: response.ok, status: response.status, data };
        })
        .then(({ ok, data }) => {
            if (!ok) {
                if (messageEl) {
                    messageEl.className = "";
                    messageEl.textContent = data.message || "Invalid username or password";
                }
                if (loginBtn) {
                    loginBtn.disabled = false;
                    loginBtn.textContent = "Login";
                }
                return;
            }

            if (messageEl) {
                messageEl.className = "success";
                messageEl.textContent = data.message || "Login successful";
            }

            // Store session metadata consistently
            localStorage.setItem("userRole", data.role);
            localStorage.setItem("username", data.username);
            localStorage.setItem("userName", data.name || data.username);
            if (data.token) {
                localStorage.setItem("authToken", data.token);
            }

            // Faculty login
            if (data.role === "faculty") {
                localStorage.removeItem("studentPRN");
                localStorage.setItem("facultyId", data.facultyId || data.username);
                window.location.href = "faculty-dashboard.html";
                return;
            }

            // Student login
            if (data.role === "student") {
                localStorage.removeItem("facultyId");
                localStorage.setItem("studentPRN", data.prn);
                if (data.className) {
                    localStorage.setItem("studentSelectedClass", data.className);
                }
                window.location.href = "student-dashboard.html";
            }
        })
        .catch(error => {
            console.error(error);
            if (messageEl) {
                messageEl.className = "";
                messageEl.textContent = "Error connecting to server. Ensure backend is running on http://localhost:3000.";
            }
            if (loginBtn) {
                loginBtn.disabled = false;
                loginBtn.textContent = "Login";
            }
        });
    });
}
