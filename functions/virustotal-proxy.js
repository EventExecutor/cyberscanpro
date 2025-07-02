const fetch = require('node-fetch');

exports.handler = async function(event) {
    if (event.httpMethod !== 'POST') {
        return { statusCode: 405, body: 'Method Not Allowed' };
    }

    try {
        const { apiKey, endpoint, options } = JSON.parse(event.body);
        const baseUrl = 'https://www.virustotal.com/api/v3';

        if (!apiKey || !endpoint) {
            return {
                statusCode: 400,
                body: JSON.stringify({ error: 'API key o endpoint mancanti' })
            };
        }

        const url = `${baseUrl}/${endpoint}`;
        
        const fetchOptions = {
            ...options,
            headers: {
                ...(options.headers || {}),
                'x-apikey': apiKey
            }
        };

        const response = await fetch(url, fetchOptions);
        const data = await response.json();

        return {
            statusCode: response.status,
            body: JSON.stringify(data)
        };

    } catch (error) {
        console.error('Errore nella funzione proxy:', error);
        return {
            statusCode: 500,
            body: JSON.stringify({ error: 'Errore interno del server proxy' })
        };
    }
};