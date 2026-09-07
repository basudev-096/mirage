const express = require("express");

const app = express();

app.use(express.json());

app.get("/", (req, res) => {
    res.status(200).json({
        server: "MIRAGE DECEPTION ENVIRONMENT",
        message: "Welcome to the application."
    });
});

app.get("/admin", (req, res) => {
    res.status(200).json({
        server: "MIRAGE DECEPTION ENVIRONMENT",
        admin: true,
        username: "admin",
        email: "admin@mirage.local",
        role: "administrator",
        apiKey: "FAKE-DEMO-KEY-12345"
    });
});
app.get("/products", (req, res) => {
    res.status(200).json({
        server: "MIRAGE DECEPTION ENVIRONMENT",
        message: "Product database accessed",
        products: [
            {
                id: 101,
                name: "Enterprise Laptop",
                price: 99999,
                internalCode: "MIRAGE-LAPTOP-01"
            },
            {
                id: 102,
                name: "Admin Keyboard",
                price: 4999,
                internalCode: "MIRAGE-KEYBOARD-02"
            },
            {
                id: 103,
                name: "Security Console",
                price: 14999,
                internalCode: "MIRAGE-CONSOLE-03"
            }
        ]
    });
});
app.get("/users", (req, res) => {
    res.status(200).json({
        server: "MIRAGE DECEPTION ENVIRONMENT",
        users: [
            {
                id: 1,
                username: "admin",
                email: "admin@mirage.local"
            },
            {
                id: 2,
                username: "john",
                email: "john@mirage.local"
            }
        ]
    });
});

app.get("/config", (req, res) => {
    res.status(200).json({
        server: "MIRAGE DECEPTION ENVIRONMENT",
        database: "fake_database",
        username: "fake_admin",
        password: "fake_password"
    });
});

function startHoneypot() {
    app.listen(5002, () => {
        console.log("Honeypot running on port 5002");
    });
}

module.exports = startHoneypot;