// getLocation.js
const fetch = require('node-fetch');

async function getLocation() {
    try {
        // We use a free IP geolocation service to find the server's location.
        // This is only used as a fallback if the user's browser doesn't provide location.
        const response = await fetch('http://ip-api.com/json/');
        if (!response.ok) {
            throw new Error(`Geolocation API failed with status: ${response.status}`);
        }

        const data = await response.json();

        if (data.status === 'fail') {
            throw new Error(`Geolocation lookup failed: ${data.message}`);
        }

        // The API returns 'lat' and 'lon'. Our app expects 'latitude' and 'longitude'.
        return {
            latitude: data.lat,
            longitude: data.lon,
            city: data.city,
            country: data.country
        };
    } catch (error) {
        console.error("Error in getLocation:", error.message);
        // It's important to return null so the part of the code calling this
        // knows that the location lookup failed.
        return null;
    }
}

module.exports = getLocation;