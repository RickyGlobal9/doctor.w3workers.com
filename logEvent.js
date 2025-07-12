const fs = require('fs').promises;

async function logEvent({ user_id, event, status }) {
    try {
        // Retrieves existing logs
        let logs = [];
        try {
            const data = await fs.readFile('./user_data/logs.json', 'utf8');
            logs = JSON.parse(data);
        } catch (error) {
            if (error.code !== 'ENOENT') throw error;
        }

        // Creates new log
        const logEntry = {
            timestamp: new Date().toISOString(),
            user_id,
            event,
            status
        };

        // Appends and writes back to file
        logs.push(logEntry);
        await fs.writeFile('./user_data/logs.json', JSON.stringify(logs, null, 2));
    } catch (error) {
        console.error('Error logging event:', error.message);
    }
}

module.exports = logEvent;