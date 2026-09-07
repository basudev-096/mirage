require("dotenv").config();

const connectDB = require("./db");
const startProxy = require("./proxy");
const startBackend = require("./backend");
const startHoneypot = require("./honeypot");

async function startSystem() {

    console.log("Starting Project Mirage...\n");

    await connectDB();

    startBackend();

    startHoneypot();

    startProxy();
}

startSystem();