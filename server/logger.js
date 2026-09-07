const Threat = require("./models/Threat");

async function logThreat(req, detection, action, tarpit = false) {
    try {
        const threat = await Threat.create({
            ip: req.ip,
            method: req.method,
            url: req.originalUrl,
            attackType: detection.attackType,
            severity: detection.severity,
            payload: JSON.stringify(req.body || {}),
            action: action,
            tarpit: tarpit
        });

        console.log("Threat logged:", threat.attackType);
    } catch (error) {
        console.error("Failed to log threat:", error.message);
    }
}

module.exports = logThreat;