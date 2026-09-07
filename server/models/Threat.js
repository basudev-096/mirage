const mongoose = require("mongoose");

const threatSchema = new mongoose.Schema({
    timestamp: {
        type: Date,
        default: Date.now
    },

    ip: {
        type: String,
        default: "unknown"
    },

    method: String,

    url: String,

    attackType: String,

    severity: {
        type: String,
        enum: ["LOW", "MEDIUM", "HIGH"],
        default: "MEDIUM"
    },

    payload: String,

    action: String,

    tarpit: {
        type: Boolean,
        default: false
    }
});

module.exports = mongoose.model("Threat", threatSchema);