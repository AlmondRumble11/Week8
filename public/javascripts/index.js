if (document.readyState !== "loading") {
    runCode();
} else {
    document.addEventListener("DOMContentLoaded", function() {
        runCode();
    });
}

function runCode() {
    let token = getToken();
    let items = [];
    const body = document.getElementById("body");
    if (token) {
        console.log("logged in ");

        //add logout btn
        const logoutBtn = document.createElement("button");
        logoutBtn.setAttribute("id", "logout");
        logoutBtn.innerText = 'Logout';

        body.appendChild(logoutBtn);


        //add the email

        const email = document.createElement("p");
        email.setAttribute("id", "email");

        //decoding the token
        //https://medium.com/@ddevinda/decode-jwt-token-6c75fa9aba6f
        let splitValue = token.split('.')[1];
        let decodedValue = JSON.parse(window.atob(splitValue));
        let token_email = decodedValue.email;

        //adding the email to web page
        console.log(decodedValue);
        email.innerHTML = token_email;
        body.appendChild(email);

        //input field to add items
        const item = document.createElement("input");
        item.type = 'text';
        item.id = 'add-item';
        body.appendChild(item);


        //list to add item
        const itemList = document.createElement("ul");
        itemList.id = 'item-list';

        body.appendChild(itemList);

        console.log("getting items from db");
        //get items from list
        fetch('/api/todos', {
            method: 'GET',
            headers: {
                "authorization": "Bearer " + token,
                "Content-type": "application/json",

            },
        }).then(res => res.json()).then(data => {
            console.log(data.items);

            //adding items to list
            for (let i = 0; i < data.items.length; i++) {
                const newItem = document.createElement('li');
                newItem.innerText = data.items[i];
                itemList.appendChild(newItem);
            }


        }).catch(err => {
            console.log(err);
        });


        //when logout is pressed
        document.getElementById('add-item').addEventListener("keypress", addItemPressed);
        document.getElementById("logout").addEventListener("click", logout);

    } else {
        const login = document.createElement("a");
        const register = document.createElement("a");
        login.innerHTML = "Login";
        register.innerHTML = "Register";
        login.setAttribute("href", "/login.html");
        register.setAttribute("href", "/register.html");
        body.appendChild(login);
        body.appendChild(register);

        console.log("not logged in ");
    }
}

function addItemPressed(event) {
    if (event.key == "Enter") {
        console.log("enter pressed");
        const item = document.getElementById("add-item");
        let itemText = item.value;
        console.log(itemText);
        let authToken = getToken();

        //add to db
        fetch("/api/todos", {
            method: 'POST',
            headers: {
                "authorization": "Bearer " + authToken,
                "Content-type": "application/json",

            },
            body: JSON.stringify({ items: itemText })
        }).then((res) => res.text()).then((data) => {
            if (data) {
                console.log("item was saved");

            }
        }).catch((err) => {
            console.log(err);
        });


    }
};

function logout() {
    localStorage.removeItem("auth_token");
    const itemList = document.getElementById('item-list');
    itemList.remove();
    window.location.href = "/";
}



function getToken() {
    console.log("getting the token");
    let token = localStorage.getItem('auth_token');
    return token;
}