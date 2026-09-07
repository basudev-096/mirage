const express = require("express");

const app = express();

app.use(express.json());

app.get("/", (req, res) => {
    res.json({
        server: "REAL PRODUCTION BACKEND",
        status: "healthy"
    });
});

app.get("/products", (req, res) => {
    res.json({
        server: "REAL PRODUCTION BACKEND",
        products: [
            {
                id: 1,
                name: "Laptop",
                price: 65000
            },
            {
                id: 2,
                name: "Keyboard",
                price: 2500
            },
            {
                id: 3,
                name: "Mouse",
                price: 1200
            }
        ]
    });
});

app.get("/profile", (req, res) => {
    res.json({
        server: "REAL PRODUCTION BACKEND",
        message: "This is legitimate application data."
    });
});

function startBackend() {
    app.listen(5001, () => {
        console.log("Real backend running on port 5001");
    });
}

module.exports = startBackend;