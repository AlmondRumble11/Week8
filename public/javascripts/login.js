if (document.readyState !== "loading") {
    runCode();
} else {
    document.addEventListener("DOMContentLoaded", function() {
        runCode();
    });
}

function runCode() {
    document.getElementById("login-form").addEventListener("submit", onSubmit);
}


function onSubmit(event) {

    event.preventDefault();
    const formData = new FormData(event.target);
    console.log("submit login");
    console.log(event.target.email);
    fetch("/users/login", {
        method: "POST",
        body: formData

    }).then((res) => res.json()).then((data) => {
        if (data.token) {
            console.log(data.token);
            storeToken(data.token);
            window.location.href = "/";
            console.log(window.location.href);

        } else {
            console.log(data.msg);
            window.location.href = "/error";

        }
    })

}

function storeToken(token) {
    console.log("storing the token");
    localStorage.setItem('auth_token', token);
}