// functions/virustotal-proxy.js

const fetch = require('node-fetch');
const multipart = require('aws-lambda-multipart-parser');
const FormData = require('form-data'); // <-- NUOVA LIBRERIA

exports.handler = async function(event) {
    const baseUrl = 'https://www.virustotal.com/api/v3';

    try {
        const contentType = event.headers['content-type'] || event.headers['Content-Type'];

        if (contentType && contentType.startsWith('multipart/form-data')) {
            // --- GESTIONE FILE CORRETTA ---
            const form = await multipart.parse(event);
            const file = form.files[0];
            const apiKey = form.apiKey;

            if (!file || !apiKey) {
                return { statusCode: 400, body: JSON.stringify({ error: 'File o API key mancanti' }) };
            }

            const uploadUrl = `${baseUrl}/files`;

            const formData = new FormData();
            // Usiamo il buffer del file direttamente, che è il modo corretto in Node.js
            formData.append('file', file.content, file.filename);

            const response = await fetch(uploadUrl, {
                method: 'POST',
                headers: { 'x-apikey': apiKey },
                body: formData // Invia il form creato con la libreria form-data
            });
            const data = await response.json();
            return { statusCode: response.status, body: JSON.stringify(data) };

        } else {
            // --- GESTIONE URL (rimane invariata) ---
            if (event.httpMethod !== 'POST') {
                return { statusCode: 405, body: 'Method Not Allowed' };
            }
            const { apiKey, endpoint, options } = JSON.parse(event.body);
            if (!apiKey || !endpoint) {
                return { statusCode: 400, body: JSON.stringify({ error: 'API key o endpoint mancanti' }) };
            }
            const url = `${baseUrl}/${endpoint}`;
            const fetchOptions = { ...options, headers: { ...(options.headers || {}), 'x-apikey': apiKey } };
            const response = await fetch(url, fetchOptions);
            const data = await response.json();
            return { statusCode: response.status, body: JSON.stringify(data) };
        }
    } catch (error) {
        console.error('Errore nella funzione proxy:', error);
        return { statusCode: 500, body: JSON.stringify({ error: 'Errore interno del server proxy', details: error.message }) };
    }
};
