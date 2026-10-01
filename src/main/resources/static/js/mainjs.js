"use strict";

const tokenKey = "jwtToken";
const message = document.getElementById("message");

async function api(path, {method = "GET", body, authenticated = false} = {}) {
    const headers = {};
    if (body) headers["Content-Type"] = "application/json";
    if (authenticated) {
        const token = sessionStorage.getItem(tokenKey);
        if (!token) {
            window.location.replace("/login");
            throw new Error("Vui lòng đăng nhập.");
        }
        headers.Authorization = "Bearer " + token;
    }
    const response = await fetch(path, {
        method, headers, body: body ? JSON.stringify(body) : undefined
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
        if (authenticated && response.status === 401) {
            sessionStorage.removeItem(tokenKey);
            window.location.replace("/login");
        }
        throw new Error(data.detail || "Không thể thực hiện yêu cầu.");
    }
    return data;
}

function bindForm(id, action) {
    const form = document.getElementById(id);
    if (!form) return;
    form.addEventListener("submit", async event => {
        event.preventDefault();
        const button = form.querySelector("button");
        button.disabled = true;
        message.textContent = "Đang xử lý…";
        try {
            await action(Object.fromEntries(new FormData(form)), form);
        } catch (error) {
            message.textContent = error.message;
        } finally {
            button.disabled = false;
        }
    });
}

bindForm("login-form", async body => {
    const data = await api("/auth/login", {method: "POST", body});
    sessionStorage.setItem(tokenKey, data.token);
    window.location.assign("/user/profile");
});

bindForm("signup-form", async (body, form) => {
    await api("/auth/signup", {method: "POST", body});
    document.querySelector('#login-form [name="email"]').value = body.email;
    form.reset();
    message.textContent = "Đăng ký thành công. Bạn có thể đăng nhập.";
});

if (document.getElementById("profile-page")) {
    document.getElementById("logout").addEventListener("click", () => {
        sessionStorage.removeItem(tokenKey);
        window.location.replace("/login");
    });

    api("/users/me", {authenticated: true}).then(user => {
        document.getElementById("full-name").textContent = user.fullName;
        document.getElementById("email").textContent = user.email;
        if (user.images) {
            const avatar = document.getElementById("avatar");
            avatar.onerror = () => { avatar.onerror = null; avatar.src = "/images/avatar.svg"; };
            avatar.src = "/images/" + encodeURIComponent(user.images);
        }
        document.getElementById("profile").hidden = false;
        message.textContent = "";
    }).catch(error => { message.textContent = error.message; });

    document.getElementById("load-users").addEventListener("click", async event => {
        event.target.disabled = true;
        try {
            const users = await api("/users", {authenticated: true});
            const list = document.getElementById("users");
            list.replaceChildren();
            users.forEach(user => {
                const item = document.createElement("li");
                item.textContent = user.fullName + " — " + user.email;
                list.appendChild(item);
            });
            message.textContent = users.length ? "" : "Chưa có người dùng.";
        } catch (error) {
            message.textContent = error.message;
        } finally {
            event.target.disabled = false;
        }
    });
}
