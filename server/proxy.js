const express = require("express");
const { createProxyMiddleware } = require("http-proxy-middleware");

const detectAttack = require("./detector");
const logThreat = require("./logger");

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));


// ===============================
// MIRAGE INSPECTION MIDDLEWARE
// ===============================

app.use((req, res, next) => {

    const detection = detectAttack(req);

    console.log("\n=================================");
    console.log("Incoming:", req.method, req.originalUrl);
    console.log("Attack:", detection.attackType);
    console.log("Severity:", detection.severity);

    if (detection.malicious) {

        console.log("🚨 MALICIOUS REQUEST");
        console.log("→ Routing to HONEYPOT :5002");

        req.mirageTarget = "honeypot";

        logThreat(
            req,
            detection,
            "HONEYPOT",
            detection.severity === "HIGH"
        );

    } else {

        console.log("✓ LEGITIMATE REQUEST");
        console.log("→ Routing to REAL BACKEND :5001");

        req.mirageTarget = "backend";
    }

    next();
});


// ===============================
// REVERSE PROXY
// ===============================

const mirageProxy = createProxyMiddleware({

    target: "http://localhost:5001",

    changeOrigin: true,

    router: function (req) {

        if (req.mirageTarget === "honeypot") {
            return "http://localhost:5002";
        }

        return "http://localhost:5001";
    },

    on: {

        proxyReq: (proxyReq, req) => {

            console.log(
                "Proxying request to:",
                req.mirageTarget === "honeypot"
                    ? "http://localhost:5002"
                    : "http://localhost:5001"
            );
        },

        proxyRes: (proxyRes, req) => {

            console.log(
                "Response received:",
                proxyRes.statusCode
            );
        },

        error: (error, req, res) => {

            console.error("❌ PROXY ERROR:", error.message);

            if (!res.headersSent) {

                res.status(502).json({
                    error: "Mirage could not reach upstream server"
                });
            }
        }
    }
});


// Catch every request and send it through Mirage
app.use(mirageProxy);


// ===============================
// START MIRAGE
// ===============================

function startProxy() {

    app.listen(5050, () => {

        console.log("=================================");
        console.log("MIRAGE PROXY running on port 5050");
        console.log("=================================");
    });
}

module.exports = startProxy;