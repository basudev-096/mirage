function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function applyTarpit(res, data) {
    const text = JSON.stringify(data);

    res.status(200);
    res.setHeader("Content-Type", "application/json");

    // Send the response slowly.
    for (const character of text) {
        res.write(character);
        await delay(1000);
    }

    res.end();
}

module.exports = {
    applyTarpit
};